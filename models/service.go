package models

type Service struct {
	ServiceName   string
	ServiceAPIKey string
	ServiceRole   string
}

type ServiceRequest struct {
	ServiceName string `json:"service_name"`
	ServiceRole string `json:"service_role"`
}
