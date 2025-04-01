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
		VTAPIKey:  "y96184c01603734518ff2ac91435bc1e6b5fa2c679be650dc49895b4425fc3c25",
	}
}
