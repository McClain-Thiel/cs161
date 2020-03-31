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

//given test for basic functionality
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

func TestInitTree(t *testing.T){
	tree := InitATree("Owner 1")
	t.Log("Type of tree is ", reflect.TypeOf(tree))
	if tree.Owner != "Owner 1"{
		t.Error("Problem initializeing tree")
	}
}

func TestTreeAdd(t *testing.T){
	clear()
	b := InitATree("Owner")
	v := InitATree("Owner")
	t.Log("Testing adding to empty Tree")
	e := TreeAdd(b, "Owner", "Child 1")
	v.Access["Owner"] = []string{"Child 1"}
	v.Access["Child 1"] = make([]string, 0)
	t.Log("Expected: ", v.Access)
	t.Log("Actual: ", b.Access)
	if e != nil || !reflect.DeepEqual(b.Access, v.Access){ //check this again
		t.Error("Problem adding in treeAdd", e)
	}
	return
}

func TestTreeRemove(t *testing.T){
	clear()

}

//loads a file that the owner owns
func TestLoadFileOwned(t *testing.T){
	clear()
	t.Log("Testing loading user owned files")
	//initialize user

}
//loads a file that has been shared with the user
func TestLoadFileShared(t *testing.T){
	clear()
	t.Log("Testing loading user owned files")
	//init user

}
//attempts to load a file that the user doesn't have premission for or doesn't exist
func TestLoadFileNotFound(t *testing.T){
	clear()
	t.Log("Testing loading user owned files")
	//init user
}
//attempts to load  file for user after permission has been revoked
func TestLoadFileRevoked(t *testing.T){
	clear()
	t.Log("Testing loading user owned files")
	//init user
}



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


func TestKeyGen(t *testing.T) {
	clear()
	username:= "jared"
	//data := []byte("this might just not compile")
	uuidBytes := userlib.RandomBytes(16)
	//id, _ := uuid.FromBytes(uuidBytes)
	token := NewAccessToken(username, uuidBytes)
	data := ParseToken(username, token)
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
	if err2 != nil{
		t.Error("Failed in TestgetSentinelAndKeys", err2)
		return
	}
} */

func TestAppend(t *testing.T) {
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
	//now test that appending works
	app := []byte("Did we pass")
	vApp := append(v, app...)
	appErr := u.AppendFile("file1", app)
	if appErr != nil {
		t.Error("There was an error whil appending the file", appErr)
		return
	}
	vApp2, appErr2 := u.LoadFile("file1")
	if appErr2 != nil {
		t.Error("Failed to upload and download the appended file", appErr2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Appended file is not the same", vApp, vApp2)
		return
	}
}

func TestKeyGen2(t *testing.T) {
	clear()
	//init access token as done when storing functions
	rd := uuid.New() //to ge the import error to shut the hell up
	fmt.Println("impoert erros my ass", rd[:1])
	username2 := "Recive"
	username1 := "Send"
	uuidbytes := userlib.RandomBytes(16)
	accessToken1 := NewAccessToken(username1, uuidbytes)
	accessToken2 := sharedAccessToken(username1, accessToken1, username2)
	fmt.Println(accessToken1, accessToken2)
	id1, sEnc1, Hmac1, _ := GenerateKeys(username1, accessToken1)
	id2, sEnc2, Hmac2, _ := GenerateKeys(username2, accessToken2)
	if id1 != id2 {
		t.Error("IDs don't match")
	} 
	if string(sEnc1) != string(sEnc2) {
		t.Error("EncKeys don't match")
	}
	if string(Hmac1) != string(Hmac2) {
		t.Error("HMACs don't match")
	}
	//test if the parse and generate key functions undo this and recover 
}
