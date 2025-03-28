package models

import "time"

type Scan struct {
	ID        string    `bson:"_id"`
	UserID    string    `bson:"userId,omitempty"`
	FileHash  string    `bson:"fileHash"`
	Result    string    `bson:"result"`
	Status    string    `bson:"status"`
	CreatedAt time.Time `bson:"createdAt"`
}
