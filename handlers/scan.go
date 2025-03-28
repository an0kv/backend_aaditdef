package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"

	"backend/config"
	"backend/database"
	"backend/models"
)

var cfg *config.Config

func ScanFile(c *gin.Context) {
	cfg = config.LoadConfig()

	var input struct {
		FileData string `json:"fileData"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	fileHash := calculateSHA256(input.FileData)

	scansCollection := database.MongoClient.Database("security").Collection("scans")
	var scan models.Scan
	err := scansCollection.FindOne(context.TODO(), bson.M{"fileHash": fileHash}).Decode(&scan)
	if err == nil {
		c.JSON(http.StatusOK, gin.H{"result": scan.Result, "status": scan.Status})
		return
	}

	newScan := models.Scan{
		ID:        fmt.Sprintf("%v", time.Now().UnixNano()),
		FileHash:  fileHash,
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	_, err = scansCollection.InsertOne(context.TODO(), newScan)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create scan record"})
		return
	}

	go func(fileHash string) {
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
			fmt.Printf("Failed to update scan result for file hash %s: %v\n", fileHash, err)
		}
		fmt.Printf("File hash %s scanned. Result: %s\n", fileHash, result)
	}(fileHash)

	c.JSON(http.StatusOK, gin.H{"message": "Scan initiated", "scanId": newScan.ID})
}

func ScanPhoneFiles(c *gin.Context) {
	cfg = config.LoadConfig()

	var input struct {
		Files []struct {
			Path string `json:"path"`
			Hash string `json:"hash"`
		} `json:"files"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	results := make([]map[string]string, 0)
	scansCollection := database.MongoClient.Database("security").Collection("scans")

	for _, file := range input.Files {
		var scan models.Scan
		err := scansCollection.FindOne(context.TODO(), bson.M{"fileHash": file.Hash}).Decode(&scan)
		if err == nil {
			results = append(results, map[string]string{
				"path":   file.Path,
				"result": scan.Result,
			})
			continue
		}

		newScan := models.Scan{
			ID:        fmt.Sprintf("%v", time.Now().UnixNano()),
			FileHash:  file.Hash,
			Status:    "pending",
			CreatedAt: time.Now(),
		}
		_, err = scansCollection.InsertOne(context.TODO(), newScan)
		if err != nil {
			results = append(results, map[string]string{
				"path":   file.Path,
				"result": "Error scanning file",
			})
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
		}(file.Path, file.Hash)

		results = append(results, map[string]string{
			"path":   file.Path,
			"result": "Scan initiated",
		})
	}

	c.JSON(http.StatusOK, gin.H{"results": results})
}

func GetScanResult(c *gin.Context) {
	scanID := c.Param("id")

	scansCollection := database.MongoClient.Database("security").Collection("scans")
	var scan models.Scan
	err := scansCollection.FindOne(context.TODO(), bson.M{"_id": scanID}).Decode(&scan)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": scan.Result, "status": scan.Status})
}

func calculateSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
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
