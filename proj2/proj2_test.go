package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestGetUser(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Initialized user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
	u1, err1 := GetUser("alice", "fubar")
	if err1 != nil {
		t.Error("Failed to get user", err1)
		return
	}
	t.Log("Got user", u1)
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

/*

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}

*/

func TestKeyGen(t *testing.T) {
	clear()
	username:= "jared"
	//data := []byte("this might just not compile")
	uuidBytes := userlib.RandomBytes(16)
	//id, _ := uuid.FromBytes(uuidBytes)
	token := newAccessToken(username, uuidBytes)
	data := parseToken(username, token)
	s := data[:16]//string version of rev_token
	if string(s) != string(uuidBytes) {
		t.Error("not the reverse")
	}
}

/*func TestUnmarshalUserCheck(t *testing.T){
	clear()
	t.Log("Testing unmarshalling users: ")
	//encrypt and store in the data store and generate hmacs
	u, err := InitUser("alice", "fubar")
	if err != nil{
		t.Error("user init error")
	}
	locationUUID, uuidError := uuid.FromBytes(u.LocationKey)
	if uuidError != nil{
		t.Error("UuidError error")
	}
	hMACKey := u.HMACKey
	symKey := u.SymKey
	u2, e := unmarshCheckUserBlob(locationUUID, hMACKey, symKey)
	if e != nil{
		t.Error("UnmarshCheckUserBlob error", e)
	}
	if u2.Username != u.Username{
		t.Error("two users did not have the same username")
	}
}
/*
func TestUnmarshalSentinelCheck(t *testing.T){
	clear()
	t.Log("Testing unmarshalling users: ")
	//encrypt and store in the data store and generate hmacs
	u, err := InitUser("alice", "fubar")
	if err != nil{
		t.Error("user init error")
	}
	locationUUID, uuidError := uuid.FromBytes(u.LocationKey)
	if uuidError != nil{
		t.Error("uuidError error")
	}
	hMACKey := u.HMACKey
	symKey := u.SymKey
	u2, e := UnmarshCheckSentinelBlob(locationUUID, hMACKey, symKey)
	if e != nil{
		t.Error("unmarshal error", e)
	}
	if u2.Username != u.Username{
		t.Error("two users did not have the same username")
	}
}

func TestUnmarshalNodeCheck(t *testing.T){
	clear()
	t.Log("testing unmarshalling users")
	//need to generate 
	u, err := InitUser("alice", "fubar")
	if err != nil{
		t.Error("user init error")
	}
	locationUUID, uuidError := uuid.FromBytes(u.LocationKey)
	if uuidError != nil{
		t.Error("uuidError error")
	}
	hMACKey := u.HMACKey
	symKey := u.SymKey
	u2, e := UnmarshCheckFileBlob(locationUUID, hMACKey, symKey)
	if e != nil{
		t.Error("unmarshal error", e)
	}
	if u2.Username != u.Username{
		t.Error("two users did not have the same username")
	}
}
*/

/*func TestGetSentinelAndKeys(t *testing.T){
	//make params user and file name
	clear()
	t.Log("Testing getSentinelAndKeys : ")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	filename := "test"
	sentinel, sentinelUUID, SymEncKey, HMACKey, err2 := GetSentinelAndKeys(u, filename)
	fmt.Println(sentinel, sentinelUUID, SymEncKey,HMACKey)
	if err2 != nil{
		t.Error("Failed in TestgetSentinelAndKeys", err2)
		return
	}
} */
