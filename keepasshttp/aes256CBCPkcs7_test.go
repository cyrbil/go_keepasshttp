package keepasshttp

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"
)

var TestKey, _ = base64.StdEncoding.DecodeString("DEBUG+256+bits++++srKysrREVCVUcrMjU2K2JpdHM=")
var TestIv, _ = base64.StdEncoding.DecodeString("DEBUG+16+CtERUJVRysxNg==")

func TestNewAES256CBCPksc7(t *testing.T) {
	type args struct {
		key []byte
		iv  []byte
	}

	tests := []struct {
		name               string
		args               args
		wantAes256cbc      bool
		wantAes256cbcEqual *aes256CBCPksc7
		wantErr            bool
	}{
		{
			name:               "should return object with good params",
			args:               args{key: TestKey, iv: TestIv},
			wantAes256cbcEqual: &aes256CBCPksc7{key: TestKey, iv: TestIv},
			wantErr:            false,
		},
		{
			name:          "should return object with nil params",
			args:          args{key: nil, iv: nil},
			wantAes256cbc: true,
			wantErr:       false,
		},
		{
			name:          "should return object with nil key",
			args:          args{key: nil, iv: TestIv},
			wantAes256cbc: true,
			wantErr:       false,
		},
		{
			name:          "should return object with nil iv",
			args:          args{key: TestKey, iv: nil},
			wantAes256cbc: true,
			wantErr:       false,
		},
		{
			name:               "should return object with too long key size",
			args:               args{key: append([]byte(TestKey), "overflow"...), iv: TestIv},
			wantAes256cbcEqual: &aes256CBCPksc7{key: TestKey, iv: TestIv},
			wantErr:            false,
		},
		{
			name:               "should return object with too long IV size",
			args:               args{key: TestKey, iv: append([]byte(TestIv), "overflow"...)},
			wantAes256cbcEqual: &aes256CBCPksc7{key: TestKey, iv: TestIv},
			wantErr:            false,
		},
		{
			name:    "should return error with bad key size",
			args:    args{key: []byte("Invalid size"), iv: TestIv},
			wantErr: true,
		},
		{
			name:    "should return error with bad iv size",
			args:    args{key: TestKey, iv: []byte("Invalid size")},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAes256cbc, err := NewAES256CBCPksc7(tt.args.key, tt.args.iv)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAES256CBCPksc7() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantAes256cbc && (gotAes256cbc == nil) {
				t.Errorf("NewAES256CBCPksc7() aes256cbc = %v, wantAes256cbc %v", gotAes256cbc, tt.wantAes256cbc)
				return
			}
			if (tt.wantAes256cbcEqual != nil) && !reflect.DeepEqual(gotAes256cbc, tt.wantAes256cbcEqual) {
				t.Errorf("NewAES256CBCPksc7() = %v, want %v", gotAes256cbc, tt.wantAes256cbcEqual)
			}
		})
	}
}

func TestAES256CBCPksc7_randBytes(t *testing.T) {
	type args struct {
		size int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "should return random bytes of specified len",
			args: args{size: 123},
		},
		{
			name:    "should return error with 0 size",
			args:    args{size: 0},
			wantErr: true,
		},
		{
			name:    "should return error negative size",
			args:    args{size: -1},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			self := &aes256CBCPksc7{}
			gotRandBytes, err := self.randBytes(tt.args.size)
			if tt.wantErr {
				if err == nil {
					t.Errorf("aes256CBCPksc7.randBytes() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if len(gotRandBytes) != tt.args.size {
				t.Errorf("aes256CBCPksc7.randBytes() = %v, want %v", len(gotRandBytes), tt.args.size)
			}
		})
	}
}

func TestAES256CBCPksc7_encrypt(t *testing.T) {
	tests := []struct {
		name               string
		key                []byte
		nilIv              bool
		data               []byte
		wantCipherText     []byte
		wantCipherTextHash string
		wantErr            bool
	}{
		{
			name:           "should encrypt small string correctly",
			data:           []byte("Hello World !"),
			wantCipherText: []byte("GD@\"\xdb\xb6\x1f\xe5\xef\x92?[p\x99\xf1\x1f"),
		},
		{
			name:               "should encrypt big string correctly",
			data:               bytes.Repeat([]byte("Hello World !"), 100000),
			wantCipherTextHash: "ba0033d46d20113c2aed3f9eb059f9c885414cdc",
		},
		{
			name:    "should raise an error with invalid key",
			key:     []byte("Invalid size"),
			wantErr: true,
		},
		{
			name:    "should raise a recovered panic error with nil arguments",
			nilIv:   true,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.key == nil {
				tt.key = TestKey
			}
			var iv []byte
			if !tt.nilIv {
				iv = TestIv
			}
			self := &aes256CBCPksc7{key: tt.key, iv: iv}
			gotCipherText, err := self.encrypt(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("aes256CBCPksc7.encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantCipherText != nil && !reflect.DeepEqual(gotCipherText, tt.wantCipherText) {
				t.Errorf("aes256CBCPksc7.encrypt() = %v, want %v", gotCipherText, tt.wantCipherText)
			}
			if tt.wantCipherTextHash != "" {
				gotHash := fmt.Sprintf("%x", sha1.Sum(gotCipherText))
				if !reflect.DeepEqual(gotHash, tt.wantCipherTextHash) {
					t.Errorf("aes256CBCPksc7.encrypt() = %v, want %v", gotHash, tt.wantCipherTextHash)
				}
			}
		})
	}
}

func TestAES256CBCPksc7_decrypt(t *testing.T) {
	tests := []struct {
		name               string
		key                []byte
		data               []byte
		wantCipherText     []byte
		wantCipherTextHash string
		wantErr            bool
	}{
		{
			name:           "should decrypt small string correctly",
			data:           []byte("Hello World !!!!"),
			wantCipherText: []byte("\xc9#\xbf.\xc6\xe5\xaf\x868'N\xba\xfe\xa5\x91l"),
		},
		{
			name:               "should decrypt big string correctly",
			data:               bytes.Repeat([]byte("Hello World !!!!"), 100000),
			wantCipherTextHash: "6335686444663cbeffbd9543db7b1ebc17bbe4ac",
		},
		{
			name:    "should raise an error with invalid key",
			key:     []byte("Invalid size"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.key == nil {
				tt.key = TestKey
			}
			self := &aes256CBCPksc7{key: tt.key, iv: TestIv}
			gotCipherText, err := self.decrypt(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("aes256CBCPksc7.decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantCipherText != nil && !reflect.DeepEqual(gotCipherText, tt.wantCipherText) {
				t.Errorf("aes256CBCPksc7.decrypt() = %v, want %v", gotCipherText, tt.wantCipherText)
			}
			if tt.wantCipherTextHash != "" {
				gotHash := fmt.Sprintf("%x", sha1.Sum(gotCipherText))
				if !reflect.DeepEqual(gotHash, tt.wantCipherTextHash) {
					t.Errorf("aes256CBCPksc7.encrypt() = %v, want %v", gotHash, tt.wantCipherTextHash)
				}
			}
		})
	}
}

func TestAES256CBCPksc7_pad(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want []byte
	}{
		{
			name: "should pad data of size n*16",
			data: []byte("byte string of length 32 -------"),
			want: []byte("byte string of length 32 -------" +
				"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"),
		},
		{
			name: "should pad data of size (n*16)-1",
			data: []byte("byte string of length 31 ------"),
			want: []byte("byte string of length 31 ------" +
				"\x01"),
		},
		{
			name: "should pad data of size (n*16)+1",
			data: []byte("byte string of length 33 --------"),
			want: []byte("byte string of length 33 --------" +
				"\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f"),
		},
		{
			name: "should pad empty data",
			data: []byte(""),
			want: []byte("\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"),
		},
		{
			name: "should pad nil data",
			data: nil,
			want: []byte("\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			self := &aes256CBCPksc7{}
			got := self.pad(tt.data)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("aes256CBCPksc7.pad() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAES256CBCPksc7_unpad(t *testing.T) {
	tests := []struct {
		name  string
		data  []byte
		want  []byte
		panic bool
	}{
		{
			name:  "should crash on nil data",
			data:  nil,
			panic: true,
		},
		{
			name: "should unpad data of size n*16",
			data: []byte("byte string of length 32 -------" +
				"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"),
			want: []byte("byte string of length 32 -------"),
		},
		{
			name: "should unpad data of size (n*16)-1",
			data: []byte("byte string of length 31 ------" +
				"\x01"),
			want: []byte("byte string of length 31 ------"),
		},
		{
			name: "should unpad data of size (n*16)+1",
			data: []byte("byte string of length 33 --------" +
				"\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f"),
			want: []byte("byte string of length 33 --------"),
		},
		{
			name: "should unpad empty data",
			data: []byte("\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"),
			want: []byte(""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			self := &aes256CBCPksc7{}
			if tt.panic {
				defer func() {
					r := recover()
					if r == nil {
						t.Errorf("aes256CBCPksc7.unpad() should have panicked")
					}
				}()
			}
			got := self.unpad(tt.data)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("aes256CBCPksc7.unpad() = %v, want %v", got, tt.want)
			}
		})
	}
}
