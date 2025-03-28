package config

type Config struct {
	MongoURI  string
	JWTSecret string
	VTAPIKey  string
}

func LoadConfig() *Config {
	return &Config{
		MongoURI:  "mongodb://localhost:27017",
		JWTSecret: "your_jwt_secret_key",
		VTAPIKey:  "your_virustotal_api_key",
	}
}
