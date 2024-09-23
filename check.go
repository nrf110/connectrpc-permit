package connectrpc_permit

import "github.com/permitio/permit-golang/pkg/enforcement"

type CheckType string

const (
	SINGLE CheckType = "single"
	BULK             = "bulk"
)

type CheckMode string

const (
	ALL_OF = "all_of"
	ANY_OF = "any_of"
)

type Attributes map[string]any

type User struct {
	Key        string
	Attributes Attributes
}

type Resource struct {
	Type       string
	Key        string
	Tenant     string
	Attributes Attributes
}

type Check struct {
	Action   string
	Resource Resource
}

func (c Check) toCheckRequest(user *User) enforcement.CheckRequest {
	permitUser := enforcement.UserBuilder(user.Key).
		WithAttributes(user.Attributes).
		Build()

	key := "*"
	if c.Resource.Key != "" {
		key = c.Resource.Key
	}

	return enforcement.CheckRequest{
		User:   permitUser,
		Action: enforcement.Action(c.Action),
		Resource: enforcement.Resource{
			Type:       c.Resource.Type,
			Key:        key,
			Tenant:     c.Resource.Tenant,
			Attributes: c.Resource.Attributes,
		},
	}
}

type CheckConfig struct {
	Type   CheckType
	Mode   CheckMode
	Checks []Check
}

type Checkable interface {
	GetChecks() CheckConfig
}
