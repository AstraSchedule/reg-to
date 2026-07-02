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

	r.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Content-Type"},
		AllowCredentials: true,
	}))

	r.GET("/api/check-subdomain/:subdomain", handler.CheckSubdomain(cfg))
	r.POST("/api/register", handler.Register(cfg))

	log.Printf("Server starting on :%s (dev=%v)", cfg.Port, cfg.Dev)
	if !cfg.Dev && (cfg.TLSCert == "" || cfg.TLSKey == "") {
		log.Println("WARNING: TLS_CERT/TLS_KEY not set, mTLS will not be used")
	}
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}
