package backends

import (
	"strings"

	"github.com/1Password/connect-sdk-go/connect"
	"github.com/1Password/connect-sdk-go/onepassword"
	"github.com/google/uuid"
)

// OnePassword is a struct for working with a OnePassword backend
type OnePassword struct {
	Client    connect.Client
	vaultUUID string
}

// NewOnePasswordBackend initializes a new OnePassword Backend
func NewOnePasswordBackend(client connect.Client, vaultUUID string) *OnePassword {
	vault := &OnePassword{
		Client:    client,
		vaultUUID: vaultUUID,
	}
	return vault
}

// Login does nothing as a "login" is handled on the instantiation of the 1password sdk
func (o *OnePassword) Login() error {
	return nil
}

func (o *OnePassword) sectionIDForName(name string, sections []*onepassword.ItemSection) string {
	if sections == nil {
		return ""
	}

	for _, s := range sections {
		if name == strings.ToLower(s.Label) {
			return s.ID
		}
	}

	return ""
}

// GetSecrets gets secrets from vault and returns the formatted data
func (o *OnePassword) GetSecrets(path string, version string, annotations map[string]string) (map[string]interface{}, error) {
	var section string

	if i := strings.Index(path, "."); i >= 0 {
		path, section = path[0:i], path[i+1:]
	}

	var isUUID bool
	if _, err := uuid.Parse(path); err == nil {
		isUUID = true
	}

	var item *onepassword.Item
	if isUUID {
		if v, err := o.Client.GetItem(path, o.vaultUUID); err != nil {
			return nil, err
		} else {
			item = v
		}
	} else {
		if v, err := o.Client.GetItemByTitle(path, o.vaultUUID); err != nil {
			return nil, err
		} else {
			item = v
		}
	}

	data := make(map[string]interface{})
	for _, f := range item.Fields {
		if section == "" {
			data[f.Label] = f.Value
		} else if f.Section.ID == section {
			data[f.Label] = f.Value
		}
	}

	return data, nil
}

// GetIndividualSecret will get the specific secret (placeholder) from the SM backend
// For OnePassword, we only support placeholders replaced from the k/v pairs of a secret which cannot be individually addressed
// So, we use GetSecrets and extract the specific placeholder we want
func (o *OnePassword) GetIndividualSecret(kvpath, secret, version string, annotations map[string]string) (interface{}, error) {
	data, err := o.GetSecrets(kvpath, version, annotations)
	if err != nil {
		return nil, err
	}
	return data[secret], nil
}
