package main

import (
	"flag"
	"log"
	"os"

	"github.com/gabrielseibel1/gaef-user-service/domain"
	"github.com/gabrielseibel1/gaef-user-service/handler"
	"github.com/gabrielseibel1/gaef-user-service/service"
	"github.com/gabrielseibel1/gaef-user-service/store"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

// dependencies

type AuthHandler interface {
	JWTAuthMiddleware() gin.HandlerFunc
}
type SignupHandler interface {
	Signup() gin.HandlerFunc
}
type LoginHandler interface {
	Login() gin.HandlerFunc
}
type TokenHandler interface {
	GetIDFromToken() gin.HandlerFunc
}
type GetHandler interface {
	GetUserFromID() gin.HandlerFunc
}
type UpdateHandler interface {
	UpdateUser() gin.HandlerFunc
}
type DeleteHandler interface {
	DeleteUser() gin.HandlerFunc
}

type handlerGenerator struct {
	authHandler   AuthHandler
	signupHandler SignupHandler
	loginHandler  LoginHandler
	tokenHandler  TokenHandler
	getHandler    GetHandler
	updateHandler UpdateHandler
	deleteHandler DeleteHandler
}

// implementation

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

	phv := domain.PasswordHasherVerifier{}
	str := store.New()
	svc := service.New(phv, phv, str, str, str, str, str)
	hdl := handler.New(svc, svc, svc, svc, svc, []byte(jwtSecret))
	gen := handlerGenerator{
		authHandler:   hdl,
		signupHandler: hdl,
		loginHandler:  hdl,
		tokenHandler:  hdl,
		getHandler:    hdl,
		updateHandler: hdl,
		deleteHandler: hdl,
	}

	r := gin.Default()
	users := r.Group("/api/v0/users")
	{
		public := users.Group("")
		{
			public.POST("/", gen.signupHandler.Signup())
			public.POST("/session", gen.loginHandler.Login())
		}
		auth := users.Group("", gen.authHandler.JWTAuthMiddleware())
		{
			auth.GET("/token-validation", gen.tokenHandler.GetIDFromToken())
			auth.GET("/:id", gen.getHandler.GetUserFromID())
			auth.PUT("/:id", gen.updateHandler.UpdateUser())
			auth.DELETE("/:id", gen.deleteHandler.DeleteUser())
		}
	}
	r.Run()
}
