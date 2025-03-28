package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"backend/config"
	"backend/database"
	"backend/models"
)

var cfg *config.Config

func StartFileScanner(directory string, interval time.Duration) {
	cfg = config.LoadConfig()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		fmt.Println("Starting scheduled file scan...")
		scanDirectory(directory)
	}
}

func scanDirectory(directory string) {
	files, err := os.ReadDir(directory)
	if err != nil {
		fmt.Printf("Failed to read directory: %v\n", err)
		return
	}

	scansCollection := database.MongoClient.Database("security").Collection("scans")

	for _, file := range files {
		filePath := filepath.Join(directory, file.Name())
		if file.IsDir() {
			scanDirectory(filePath)
			continue
		}

		fileHash, err := calculateFileHash(filePath)
		if err != nil {
			fmt.Printf("Failed to calculate hash for file %s: %v\n", filePath, err)
			continue
		}

		var scan models.Scan
		err = scansCollection.FindOne(context.TODO(), bson.M{"fileHash": fileHash}).Decode(&scan)
		if err == nil {
			fmt.Printf("File %s already scanned. Result: %s\n", filePath, scan.Result)
			continue
		}

		newScan := models.Scan{
			ID:        fmt.Sprintf("%v", time.Now().UnixNano()),
			FileHash:  fileHash,
			Status:    "pending",
			CreatedAt: time.Now(),
		}
		_, err = scansCollection.InsertOne(context.TODO(), newScan)
		if err != nil {
			fmt.Printf("Failed to create scan record for file %s: %v\n", filePath, err)
			continue
		}

		go func(filePath string, fileHash string) {
			result, err := checkFileWithVirusTotal(fileHash, cfg.VTAPIKey)
			if err != nil {
				fmt.Printf("Error scanning file: %v\n", err)
				result = "Error scanning file"
			}

			_, err = scansCollection.UpdateOne(
				context.TODO(),
				bson.M{"fileHash": fileHash},
				bson.M{"$set": bson.M{"result": result, "status": "completed"}},
			)
			if err != nil {
				fmt.Printf("Failed to update scan result for file %s: %v\n", filePath, err)
			}
			fmt.Printf("File %s scanned. Result: %s\n", filePath, result)
		}(filePath, fileHash)
	}
}

func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func checkFileWithVirusTotal(fileHash string, vtAPIKey string) (string, error) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", fileHash)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("x-apikey", vtAPIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %v", err)
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid response format")
	}

	attributes, ok := data["attributes"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid response format")
	}

	stats, ok := attributes["last_analysis_stats"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid response format")
	}

	maliciousCount, _ := stats["malicious"].(float64)
	if maliciousCount > 0 {
		return "Malicious content detected", nil
	}

	return "No threats detected", nil
}
