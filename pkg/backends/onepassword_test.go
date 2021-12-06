package backends_test

import (
	"reflect"
	"testing"

	"github.com/1Password/connect-sdk-go/onepassword"
	"github.com/google/uuid"

	"github.com/argoproj-labs/argocd-vault-plugin/pkg/backends"
)

type mockOnePasswordClient struct{}

func (mc *mockOnePasswordClient) GetVaults() ([]onepassword.Vault, error) {
	return nil, nil
}
func (mc *mockOnePasswordClient) GetVault(uuid string) (*onepassword.Vault, error) {
	return nil, nil
}
func (mc *mockOnePasswordClient) GetVaultsByTitle(uuid string) ([]onepassword.Vault, error) {
	return nil, nil
}
func (mc *mockOnePasswordClient) GetItem(id string, vaultUUID string) (*onepassword.Item, error) {
	var data *onepassword.Item
	switch id {
	case "b6c0c767-3080-44b8-bd9f-4aa86823738c":
		data = &onepassword.Item{
			ID: id,
			Vault: onepassword.ItemVault{
				ID: vaultUUID,
			},
			Sections: []*onepassword.ItemSection{{
				ID:    "",
				Label: "section",
			}},
			Fields: []*onepassword.ItemField{{
				ID:    uuid.New().String(),
				Label: "test-secret",
				Value: "current-value",
			}},
		}
	}
	return data, nil
}

func (mc *mockOnePasswordClient) GetItems(vaultUUID string) ([]onepassword.Item, error) {
	return nil, nil
}
func (mc *mockOnePasswordClient) GetItemsByTitle(title string, vaultUUID string) ([]onepassword.Item, error) {
	return nil, nil
}
func (mc *mockOnePasswordClient) GetItemByTitle(title string, vaultUUID string) (*onepassword.Item, error) {
	var data *onepassword.Item
	switch title {
	case "test":
		data = &onepassword.Item{
			ID:    uuid.New().String(),
			Title: title,
			Vault: onepassword.ItemVault{
				ID: vaultUUID,
			},
			Sections: []*onepassword.ItemSection{{
				ID:    "",
				Label: "section",
			}},
			Fields: []*onepassword.ItemField{{
				ID:    uuid.New().String(),
				Label: "test-secret",
				Value: "current-value",
			}},
		}
	}
	return data, nil
}
func (mc *mockOnePasswordClient) CreateItem(item *onepassword.Item, vaultUUID string) (*onepassword.Item, error) {
	return nil, nil
}
func (mc *mockOnePasswordClient) UpdateItem(item *onepassword.Item, vaultUUID string) (*onepassword.Item, error) {
	return nil, nil
}
func (mc *mockOnePasswordClient) DeleteItem(item *onepassword.Item, vaultUUID string) error {
	return nil
}
func (mc *mockOnePasswordClient) DeleteItemByID(itemUUID string, vaultUUID string) error {
	return nil
}
func (mc *mockOnePasswordClient) GetFiles(itemUUID string, vaultUUID string) ([]onepassword.File, error) {
	return nil, nil
}
func (mc *mockOnePasswordClient) GetFile(fileUUID string, itemUUID string, vaultUUID string) (*onepassword.File, error) {
	return nil, nil
}
func (mc *mockOnePasswordClient) GetFileContent(file *onepassword.File) ([]byte, error) {
	return nil, nil
}
func (mc *mockOnePasswordClient) DownloadFile(file *onepassword.File, targetDirectory string, overwrite bool) (string, error) {
	return "", nil
}
func (mc *mockOnePasswordClient) LoadStructFromItemByTitle(config interface{}, itemTitle string, vaultUUID string) error {
	return nil
}
func (mc *mockOnePasswordClient) LoadStructFromItem(config interface{}, itemUUID string, vaultUUID string) error {
	return nil
}
func (mc *mockOnePasswordClient) LoadStruct(config interface{}) error {
	return nil
}

func TestOnePasswordGetSecrets(t *testing.T) {
	sm := backends.NewOnePasswordBackend(&mockOnePasswordClient{}, uuid.New().String())

	t.Run("Get secrets by title", func(t *testing.T) {
		data, err := sm.GetSecrets("test", "", map[string]string{})
		if err != nil {
			t.Fatalf("expected 0 errors but got: %s", err)
		}

		expected := map[string]interface{}{
			"test-secret": "current-value",
		}

		if !reflect.DeepEqual(expected, data) {
			t.Errorf("expected: %s, got: %s.", expected, data)
		}
	})

	t.Run("Get secrets by uuid", func(t *testing.T) {
		data, err := sm.GetSecrets("b6c0c767-3080-44b8-bd9f-4aa86823738c", "", map[string]string{})
		if err != nil {
			t.Fatalf("expected 0 errors but got: %s", err)
		}

		expected := map[string]interface{}{
			"test-secret": "current-value",
		}

		if !reflect.DeepEqual(expected, data) {
			t.Errorf("expected: %s, got: %s.", expected, data)
		}
	})

	t.Run("1Password GetIndividualSecret by title", func(t *testing.T) {
		secret, err := sm.GetIndividualSecret("test", "test-secret", "", map[string]string{})
		if err != nil {
			t.Fatalf("expected 0 errors but got: %s", err)
		}

		expected := "current-value"

		if !reflect.DeepEqual(expected, secret) {
			t.Errorf("expected: %s, got: %s.", expected, secret)
		}
	})

	t.Run("1Password GetIndividualSecret by uuid", func(t *testing.T) {
		secret, err := sm.GetIndividualSecret("b6c0c767-3080-44b8-bd9f-4aa86823738c", "test-secret", "", map[string]string{})
		if err != nil {
			t.Fatalf("expected 0 errors but got: %s", err)
		}

		expected := "current-value"

		if !reflect.DeepEqual(expected, secret) {
			t.Errorf("expected: %s, got: %s.", expected, secret)
		}
	})
}

func TestOnePasswordEmptyIfNoSecret(t *testing.T) {
	sm := backends.NewOnePasswordBackend(&mockOnePasswordClient{}, uuid.New().String())

	_, err := sm.GetSecrets("empty", "", map[string]string{})
	if err == nil {
		t.Fatalf("expected an error but got nil")
	}

	if err.Error() != "Could not find secret empty" {
		t.Errorf("expected error: %s, got: %s.", "Could not find secret empty", err.Error())
	}
}
