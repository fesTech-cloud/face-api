package interfacex

import "github.com/google/uuid"

type CreateAccountRequest struct {
	BrandName string    `json:"brand_name" binding:"required"`
	Email     string    `json:"email" binding:"required,email"`
	Password  string    `json:"password" binding:"required,min=8"`
	PlanID    uuid.UUID `json:"plan_id" binding:"required,uuid"`
}

// TODO only Authenticated User Can Access
type CreateAPIKeyRequest struct {
	IsLive bool      `json:"is_live" binding:"required"`
	UserID uuid.UUID `json:"user_id"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type UserResponse struct {
	ID        uuid.UUID `json:"id"`
	BrandName string    `json:"brand_name"`
	Email     string    `json:"email"`
	PlanID    uuid.UUID `json:"plan_id"`
}

type CreatePlanRequest struct {
	Name        string `json:"name" binding:"required"`
	CallLimit   int    `json:"call_limit" binding:"required"`
	PriceNaira  int    `json:"price_naira" binding:"required"`
}

type ActivatePlanRequest struct {
	PlanID uuid.UUID `json:"plan_id" binding:"required"`
}
