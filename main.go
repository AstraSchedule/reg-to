package main

import (
	"log"
	"reg-to/config"
	"reg-to/handler"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()
	r := gin.Default()

	allowOrigins := []string{"*"}
	if !cfg.Dev {
		allowOrigins = []string{"https://go.getastra.cn"}
	}

	r.Use(cors.New(cors.Config{
		AllowOrigins:     allowOrigins,
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Content-Type"},
		AllowCredentials: true,
	}))

	r.GET("/api/check-subdomain/:subdomain", handler.CheckSubdomain(cfg))
	r.POST("/api/register", handler.Register(cfg))

	log.Printf("Server starting on :%s", cfg.Port)
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}
