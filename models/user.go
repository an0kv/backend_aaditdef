package models

import "time"

type User struct {
	ID        string    `bson:"_id"`
	Email     string    `bson:"email"`
	Password  string    `bson:"password"`
	CreatedAt time.Time `bson:"createdAt"`
}
