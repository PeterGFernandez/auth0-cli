package display

import (
	"fmt"

	"github.com/auth0/go-auth0/management"

	"github.com/auth0/auth0-cli/internal/ansi"
)

type identityView struct {
	Connection string
	Provider   string
	ID         string
	raw        interface{}
}

func (v *identityView) AsTableHeader() []string {
	return []string{"Connection", "Provider", "ID"}
}

func (v *identityView) AsTableRow() []string {
	return []string{
		v.Connection,
		v.Provider,
		ansi.Faint(v.ID),
	}
}

func (v *identityView) KeyValues() [][]string {
	return [][]string{
		{"CONNECTION", v.Connection},
		{"PROVIDER", v.Provider},
		{"ID", ansi.Faint(v.ID)},
	}
}

func (v *identityView) Object() interface{} {
	return v.raw
}

func (r *Renderer) UserIdentityList(identities []*management.UserIdentity) {
	resource := "user identities"
	r.Heading(fmt.Sprintf("%s (%d)", resource, len(identities)))

	if len(identities) == 0 {
		//		r.EmptyState(resource, "Use 'auth0 users roles assign' to assign roles to a user")
		return
	}

	var res []View
	for _, identity := range identities {
		res = append(res, makeIdentityView(identity))
	}

	r.Results(res)
}

func makeIdentityView(identity *management.UserIdentity) *identityView {
	return &identityView{
		Connection: *identity.Connection,
		Provider:   *identity.Provider,
		ID:         ansi.Faint(*identity.UserID),
		raw:        identity,
	}
}
