package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gabrielseibel1/gaef-user-service/domain"
	"github.com/gabrielseibel1/gaef-user-service/service"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

type Handler interface {
	JWTAuthMiddleware() func(ctx *gin.Context)
	Signup() func(ctx *gin.Context)
	Login() func(ctx *gin.Context)
	GetIDFromToken() func(ctx *gin.Context)
	GetUserFromID() func(ctx *gin.Context)
	UpdateUser() func(ctx *gin.Context)
	DeleteUser() func(ctx *gin.Context)
}

type serviceHandler struct {
	service   service.Service
	jwtSecret []byte
}

const jwtTTL = time.Hour * 24 * 7

func New(service service.Service, jwtSecret []byte) Handler {
	return &serviceHandler{
		service:   service,
		jwtSecret: jwtSecret,
	}
}

func (sh serviceHandler) JWTAuthMiddleware() func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" || len(authHeader) <= len("Bearer ") {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing authorization header"})
			return
		}
		authHeader = authHeader[len("Bearer "):]

		token, err := jwt.Parse(authHeader, func(token *jwt.Token) (interface{}, error) {
			return sh.jwtSecret, nil
		})
		fmt.Println(token)
		if err != nil || !token.Valid {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}
		tokenUserID := claims["sub"].(string)

		paramUserID := ctx.Param("id")
		if paramUserID != "" && tokenUserID != paramUserID {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		ctx.Set("AuthenticatedUserID", tokenUserID)

		ctx.Next()
	}
}

func (sh serviceHandler) Signup() func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		var json struct {
			Name     string `json:"name" binding:"required"`
			Email    string `json:"email" binding:"required"`
			Password string `json:"password" binding:"required"` // TODO: password requirements validation
		}
		if err := ctx.ShouldBindJSON(&json); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		user := &domain.User{
			Email: json.Email,
			Name:  json.Name,
		}
		id, err := sh.service.Create(user, json.Password)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		ctx.JSON(http.StatusCreated, gin.H{"id": id})
	}
}

func (sh serviceHandler) Login() func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		var json struct {
			Email    string `json:"email" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := ctx.ShouldBindJSON(&json); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized"})
			return
		}

		id, err := sh.service.Login(json.Email, json.Password)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		user, err := sh.service.Read(id)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"name":  user.Name,
			"email": user.Email,
			"sub":   user.ID,
			"exp":   time.Now().Add(jwtTTL).Unix(),
		})
		tokenString, err := token.SignedString(sh.jwtSecret)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"token": tokenString})
	}
}

func (sh serviceHandler) GetIDFromToken() func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		id := ctx.GetString("AuthenticatedUserID")
		ctx.JSON(http.StatusOK, gin.H{"id": id})
	}
}

func (sh serviceHandler) GetUserFromID() func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		id := ctx.Param("id")
		user, err := sh.service.Read(id)
		if err != nil {
			ctx.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"user": user})
	}
}

func (sh serviceHandler) UpdateUser() func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		var providedUser domain.User
		if err := ctx.ShouldBindJSON(&providedUser); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if providedUser.ID != ctx.GetString("AuthenticatedUserID") {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		updatedUser, err := sh.service.Update(&providedUser)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"user": updatedUser})
	}
}

func (sh serviceHandler) DeleteUser() func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		id := ctx.GetString("AuthenticatedUserID")

		err := sh.service.Delete(id)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("deleted user %s", id)})
	}
}
