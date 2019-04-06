package keepasshttp

import (
	"encoding/base64"
	"reflect"
)

// mixup of request/response body fields
type body struct {
	// request fields
	Id            string `json:",omitempty"`
	Key           string `json:",omitempty"`
	RequestType   string `json:",omitempty"`
	SortSelection bool   `json:",string,omitempty"`
	TriggerUnlock bool   `json:",string,omitempty"`

	// request encrypted fields
	Url       string `json:",omitempty" encrypted:"aes"`
	SubmitUrl string `json:",omitempty" encrypted:"aes"`
	Uuid      string `json:",omitempty" encrypted:"aes"`
	Realm     string `json:",omitempty" encrypted:"aes"`
	Login     string `json:",omitempty" encrypted:"aes"`
	Password  string `json:",omitempty" encrypted:"aes"`

	// response fields
	Success    bool   `json:",omitempty"`
	Error      string `json:",omitempty"`
	Hash       string `json:",omitempty"`
	Nonce      string `json:",omitempty"`
	Version    string `json:",omitempty"`
	ObjectName string `json:"objectName,omitempty"`
	Verifier   string `json:",omitempty" encrypted:"aes"`

	// credential response fields
	Count   int          `json:",omitempty"`
	Entries []*bodyEntry `json:",omitempty"`
}

type bodyEntry struct {
	Uuid         string                  `json:",omitempty" encrypted:"aes"`
	Url          string                  `json:",omitempty" encrypted:"aes"`
	SubmitUrl    string                  `json:",omitempty" encrypted:"aes"`
	Login        string                  `json:",omitempty" encrypted:"aes"`
	Password     string                  `json:",omitempty" encrypted:"aes"`
	StringFields []*bodyEntryStringField `json:",omitempty"`
}

type bodyEntryStringField struct {
	Key   string `json:",omitempty" encrypted:"aes"`
	Value string `json:",omitempty" encrypted:"aes"`
}

func (aes256 *aes256CBCPksc7) encryptBase64String(clearText string) (string, error) {
	clearBytes := []byte(clearText)
	cipherBytes, err := aes256.encrypt(clearBytes)
	if err != nil {
		return "", err
	}
	cipherText := base64.StdEncoding.EncodeToString(cipherBytes)
	return cipherText, nil
}

func (aes256 *aes256CBCPksc7) decryptBase64String(cipherText string) (string, error) {
	cipherBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	clearBytes, err := aes256.decrypt(cipherBytes)
	if err != nil {
		return "", err
	}
	clearText := string(clearBytes)
	return clearText, nil
}

func (kph *keePassHTTP) encryptBody(aes *aes256CBCPksc7, data *body) error {
	return applyToTag(reflect.ValueOf(data), "encrypted", aes.encryptBase64String)
}

func (kph *keePassHTTP) decryptBody(aes *aes256CBCPksc7, data *body) error {
	return applyToTag(reflect.ValueOf(data), "encrypted", aes.decryptBase64String)
}

func applyToTag(value reflect.Value, tagFilter string, convert func(string) (string, error)) error {
	valueKind := value.Kind()

	switch valueKind {
	case reflect.Array, reflect.Slice:
		numEntries := value.Len()
		for i := 0; i < numEntries; i++ {
			entry := value.Index(i)
			err := applyToTag(entry, tagFilter, convert)
			if err != nil {
				return err
			}
		}
	case reflect.Struct:
		valueType := value.Type()
		numFields := valueType.NumField()
		for i := 0; i < numFields; i++ {
			field := valueType.Field(i)
			fieldType := field.Type
			fieldKind := fieldType.Kind()
			if fieldKind == reflect.String {
				tags := field.Tag
				tag := tags.Get(tagFilter)
				if tag == "" {
					continue
				}
				fieldValue := value.Field(i)
				raw := fieldValue.String()
				if raw == "" {
					continue
				}
				dec, err := convert(raw)
				if err != nil {
					return err
				}
				fieldValue.SetString(dec)
			} else {
				valueField := value.Field(i)
				err := applyToTag(valueField, tagFilter, convert)
				if err != nil {
					return err
				}
			}
		}
	case reflect.Ptr:
		err := applyToTag(value.Elem(), tagFilter, convert)
		if err != nil {
			return err
		}
	}

	return nil
}
