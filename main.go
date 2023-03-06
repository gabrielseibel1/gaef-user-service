package main

import (
	"flag"
	"log"
	"os"

	"github.com/gabrielseibel1/gaef-user-service/handler"
	"github.com/gabrielseibel1/gaef-user-service/service"
	"github.com/gabrielseibel1/gaef-user-service/store"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	var prod bool
	flag.BoolVar(&prod, "production", false, "indicates the service is used for production")
	flag.Parse()

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	var jwtSecret string
	if prod {
		jwtSecret = os.Getenv("JWT_SECRET")
	} else {
		jwtSecret = "debug-jwt-secret"
	}

	str := store.New()
	svc := service.New(str)
	hdl := handler.New(svc, []byte(jwtSecret))

	r := gin.Default()
	users := r.Group("/api/v0/users")
	{
		public := users.Group("")
		{
			public.POST("/", hdl.Signup())
			public.POST("/session", hdl.Login())
		}
		auth := users.Group("", hdl.JWTAuthMiddleware())
		{
			auth.GET("/token-validation", hdl.GetIDFromToken())
			auth.GET("/:id", hdl.GetUserFromID())
			auth.PUT("/:id", hdl.UpdateUser())
			auth.DELETE("/:id", hdl.DeleteUser())
		}
	}
	r.Run()
}
