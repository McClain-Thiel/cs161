package proj2

// CS 161 Project 2 Spring 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You need to add with:
	// go get github.com/cs161-staff/userlib

	"fmt"

	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with: go get github.com/google/uuid
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// hardcoded master key used for the
const MASTER_KEY string = "jaredandmcclain!"

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

/*
TODO: implement private functions for server use
Our implemntation makes use of a private data store which holds all data (encrypted) until
a user requests it, at which point the server fetches the file and decrypts it then re-encrypts
using the users public key and puts the encrypted file in the public datastore.

classes:
	Server: thing that holds the datastores and does actions required by the backend
	File: stores the data, owner and list of users who have access

Functions:
	store_file(owner, shared_with, file_data, file_name):
	get_file(requester, file_name):

*/

type Blob struct {
	JsonData []byte //holds the encrypted data of either a file or user instance
	DataHMAC []byte //holds the HMAC of the encrypted data
	//special attributes for dealing with files as opposed to users
	Owner       User     //not correct data type possibly
	Shared_with []string //usernames...?
}

// The structure definition for a user record
type User struct {
	Username    string
	MasterKey   []byte               //will be used to verify password and generate other keys for the user
	LocationKey []byte               //will be used to find the location of the user in datastore
	SymKey      []byte               //will be used as this user's symmetric key for encryption
	HMACKey     []byte               //will be used as this user's HMACKey
	PrivateKey  userlib.PKEDecKey    //will be used as this user's private key
	DigSig      userlib.DSSignKey    //will be used to sign data from the user
	OwnedFiles  map[string]uuid.UUID //{hashed filename: uuid (location in Datastore)} files owned by this user
	SharedFiles map[string]uuid.UUID //{hashed filename: uuid (location in Datastore)} files shared with this user
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.
//NEED TO MAKE SEPARATE KEYS
func InitUser(username string, password string) (userdataptr *User, err error) {
	// check if this username is already in use
	_, exists := userlib.KeystoreGet(username + "_PKE")
	if exists {
		return nil, errors.New("This username already exists")
	}
	// create a new instance of a user
	var userdata User
	userdataptr = &userdata
	userdata.Username = username
	userdata.OwnedFiles = make(map[string]uuid.UUID)
	userdata.SharedFiles = make(map[string]uuid.UUID) //check this syntax
	// generate the master key
	MasterKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	userdata.MasterKey = MasterKey
	// generate keys
	HMACKey, HMACError := userlib.HashKDF(MasterKey, []byte("HMAC"))
	LocationKey, LocationError := userlib.HashKDF(MasterKey, []byte("Location"))
	SymKey, SymError := userlib.HashKDF(MasterKey, []byte("Symmetric Encryption"))
	PublicKeyEnc, PrivateKeyEnc, PKEError := userlib.PKEKeyGen()
	PrivateKeyDS, PublicKeyDS, DSError := userlib.DSKeyGen()
	//check for errors in key generation
	if HMACError != nil || LocationError != nil || SymError != nil || PKEError != nil || DSError != nil {
		return nil, errors.New("An error has occurred while generating the user's keys.")
	}
	//assign keys to userdata.Keys
	userdata.HMACKey = HMACKey[:16]
	userdata.LocationKey = LocationKey[:16]
	userdata.SymKey = SymKey[:32]
	userdata.PrivateKey = PrivateKeyEnc
	userdata.DigSig = PrivateKeyDS
	//store the public keys in keystore
	userlib.KeystoreSet(username+"_PKE", PublicKeyEnc)
	userlib.KeystoreSet(username+"_DS", PublicKeyDS)
	// userdata is now complete, now we must instantiate a Blob for this user to store securely in datastore
	var userblob Blob
	marshalledData, marshallError := json.Marshal(userdata)
	userblob.JsonData = userlib.SymEnc(userdata.SymKey, userlib.RandomBytes(16), marshalledData)
	DataHMAC, MACError := userlib.HMACEval(userdata.HMACKey, userblob.JsonData)
	userblob.DataHMAC = DataHMAC
	//store the blob in Datastore
	locationUUID, uuidError := uuid.FromBytes(userdata.LocationKey)
	marshalledBlob, marshallBlobError := json.Marshal(userblob)
	//check for errors in building blob intance
	if marshallError != nil || MACError != nil || uuidError != nil || marshallBlobError != nil {
		fmt.Println(marshallError, MACError, uuidError, marshallBlobError)
		return nil, errors.New("An error has occured while encrypting the user information.")
	}
	userlib.DatastoreSet(locationUUID, marshalledBlob)
	//return a pointer to the user
	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.

//'im drawing a blank here dawg, we gotta like unencrypt our shit'
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	//first check if the user exists
	_, exists := userlib.KeystoreGet(username + "_PKE")
	if !exists {
		return nil, errors.New("The user cannot be found")
	}
	//now check if username and password are correct
	//generate the user's master key
	userMK := userlib.Argon2Key([]byte(password), []byte(username), 16)
	//generate the user's location key
	LocationKey, LocationError := userlib.HashKDF(userMK, []byte("Location"))
	locationUUID, uuidError := uuid.FromBytes(LocationKey[:16])
	//grab the blob from Datastore
	marshalled, correctInfo := userlib.DatastoreGet(locationUUID)
	if !correctInfo {
		return nil, errors.New("The username and/or password is incorrect")
	}
	//now check that the user data has not been tampered with
	//unmarshal the data
	var unmarshalled Blob
	marshalError1 := json.Unmarshal(marshalled, &unmarshalled)
	//unravel unmarshalleded blob object
	encryptedUser := unmarshalled.JsonData
	reportedHMAC := unmarshalled.DataHMAC
	//generate the user's HMACKey
	HMACKey, HMACError := userlib.HashKDF(userMK, []byte("HMAC"))
	//compute HMAC from unencryptedUser
	actualHMAC, HMACGenError := userlib.HMACEval(HMACKey[:16], encryptedUser) //idk what this key is supposed to be
	//compare to reportedHMAC
	if !userlib.HMACEqual(reportedHMAC, actualHMAC) {
		return nil, errors.New("User data has been tampered with")
	}
	//If we reach this point, our user data is good to go, so we can assign it to userdata
	//generate the user's symmetric key
	SymKey, SymError := userlib.HashKDF(userMK, []byte("Symmetric Encryption"))
	//unencrypt then unmarshall the user data
	unencryptedMarshalledUser := userlib.SymDec(SymKey[:32], encryptedUser)
	unmarshalError2 := json.Unmarshal(unencryptedMarshalledUser, &userdata)
	if LocationError != nil || uuidError != nil || HMACError != nil || HMACGenError != nil || SymError != nil || marshalError1 != nil || unmarshalError2 != nil {
		return nil, errors.New("tuff shit. log off")
	}
	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	//TODO: This is a toy implementation.
	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	packaged_data, _ := json.Marshal(data)
	userlib.DatastoreSet(UUID, packaged_data)
	//End of toy implementation

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	//TODO: This is a toy implementation.
	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	packaged_data, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	json.Unmarshal(packaged_data, &data)
	return data, nil
	//End of toy implementation

	return
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	return
}
