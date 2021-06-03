package scp03

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"sync"

	"github.com/aead/cmac"
	"github.com/pkg/errors"
	"github.com/skythen/apdu"
)

// SessionKeyProvider is the interface that provides session key derivation.
type SessionKeyProvider interface {
	// ProvideSessionKey provides an AES session key by using the static AES key
	// with the given Key ID and Key Version Number and by using it with the data derivation
	// function specified in NIST SP 800-108.
	//
	// The result of the application of the KDF (which is the derived session key) is provided in dst.
	//
	// The PRF used in the KDF shall be CMAC as specified in NIST 800-38B, used with full 16-byte output length.
	// The “fixed input data” plus iteration counter for the KDF is the concatenation of the following items in the given sequence:
	// 		A 12-byte “label” consisting of 11 bytes with value '00' followed by a 1-byte derivation constant as defined below.
	//		A 1-byte “separation indicator” with value '00'.
	//		A 2-byte integer “L” specifying the length in bits of the derived data (value '0040', '0080', '00C0', or '0100').
	//		A 1-byte counter “i” as specified in the KDF (which may take the values '01' or '02'; value '02' is used when “L” takes the values '00C0' and '0100', i.e. when the PRF of the KDF is to be called twice to generate enough derived data).
	//		The “context” parameter of the KDF.
	//
	// Key ID and Key Version Number uniquely identify the key of a Security Domain that shall be used for the
	// Secure Channel Session.
	//
	// Key Diversification Data returned in the response to the INITIALIZE UPDATE command may be used for the derivation of static keys.
	ProvideSessionKey(dst []byte, label []byte, context []byte, keyID byte, kvn byte, diversificationData []byte) error

	// KeyByteSize returns the size of a key in the key set with the given Key Version Number in bytes.
	KeyByteSize(kvn byte) (int, error)
}

// Transmitter is the interface that transmits apdu.Capdu and returns apdu.Rapdu.
type Transmitter interface {
	Transmit(capdu apdu.Capdu) (apdu.Rapdu, error)
}

// CommandSecurityLevel represents the security level options applicable for commands.
type CommandSecurityLevel int

const (
	CMAC        CommandSecurityLevel = iota // Apply only CMAC on commands.
	CMACAndCDEC CommandSecurityLevel = iota // Apply CMAC and CDEC on commands.
)

// ResponseSecurityLevel represents the security level options applicable for responses.
type ResponseSecurityLevel int

const (
	None        ResponseSecurityLevel = iota // Apply nothing on responses.
	RMAC        ResponseSecurityLevel = iota // Apply only RMAC on responses.
	RMACAndRENC ResponseSecurityLevel = iota // Apply RMAC and RENC on responses.
)

// ConfigureResponseSecurityLevel is a function that takes the indication of R-MAC and R-ENC support
// and returns a ResponseSecurityLevel. It is used to set the response Security Level
// depending on the options indicated by the response to INITIALIZE UPDATE.
type ConfigureResponseSecurityLevel func(rmacSupport bool, rencSupport bool) ResponseSecurityLevel

// InitiationConfiguration is the configuration for the explicit initiation of a Secure Channel Session.
type InitiationConfiguration struct {
	CommandSecurityLevel CommandSecurityLevel // Security Level applied for Command APDUs.
	ChannelID            uint8                // ID of the base/logical channel the SCP session shall be initiated on. Should be in range of 0-19.
	KeyVersionNumber     uint8                // Key Version Number within the Security Domain to be used to initiate the Secure Channel Session. If this value is zero, the first available key chosen by the Security Domain will be used.
	HostChallenge        [8]byte              // Host Challenge used in the INITIALIZE UPDATE command and as part of 'context' for session key derivation.
}

// CardCryptogramError results from a mismatch between the card cryptogram calculated on host and the card cryptogram received from the card.
type CardCryptogramError struct {
	Expected []byte // Expected card cryptogram.
	Received []byte // Received card cryptogram.
}

func (e CardCryptogramError) Error() string {
	return fmt.Sprintf("scp03: invalid card cryptogram: expected: %02X received: %02X", e.Expected, e.Received)
}

// KeyDerivationError results from an error during the derivation of session keys.
type KeyDerivationError struct {
	Message string
	Cause   error
}

func (e KeyDerivationError) Error() string {
	return fmt.Sprintf("scp03: key derivation failed: %s cause: %e", e.Message, e.Cause)
}

// NonSuccessResponseError results from receiving a Response APDU with a non-success status word.
type NonSuccessResponseError struct {
	Command  apdu.Capdu // CAPDU that was transmitted.
	Response apdu.Rapdu // RAPDU that has been received.
}

func (e NonSuccessResponseError) Error() string {
	return fmt.Sprintf("scp03: received non success response CAPDU: %s RAPDU: %s", e.Command.String(), e.Response.String())
}

// TransmitError results from an error during the transmission of a Command APDU.
type TransmitError struct {
	Command apdu.Capdu // CAPDU that should have been transmitted.
	Cause   error
}

func (e TransmitError) Error() string {
	return fmt.Sprintf("scp03: transmit of command failed CAPDU: %s cause: %e", e.Command.String(), e.Cause)
}

// InitiateChannel uses explicit initiation to create a Secure Channel to the currently selected application
// (or associated Security Domain) and returns a Session.
//
// Transmitter.Transmit is called to transmit the INITIALIZE UPDATE and
// EXTERNAL AUTHENTICATE CAPDUs and receive the RAPDUs.
//
// SessionKeyProvider.KeyByteSize is called to determine the size of session keys.
// SessionKeyProvider.ProvideSessionKey is called two to three times (depending on the configured Security Level)
// to derive session keys from the static keys ENC and MAC.
//
// ConfigureResponseSecurityLevel is called to configure the response Security Level after receiving the INITIALIZE UPDATE response.
func InitiateChannel(config InitiationConfiguration, transmitter Transmitter, keyProvider SessionKeyProvider, configureResponseSecurityLevel ConfigureResponseSecurityLevel) (*Session, error) {
	initUpdate := apdu.Capdu{
		Cla:  onLogicalChannel(config.ChannelID, 0x80),
		Ins:  0x50,
		P1:   config.KeyVersionNumber,
		P2:   0x00,
		Data: config.HostChallenge[:],
		Ne:   apdu.MaxLenResponseDataStandard,
	}

	resp, err := transmitter.Transmit(initUpdate)
	if err != nil {
		return nil, TransmitError{Command: initUpdate, Cause: err}
	}

	if !resp.IsSuccess() {
		return nil, NonSuccessResponseError{
			Command:  initUpdate,
			Response: resp,
		}
	}

	iur, err := parseInitializeUpdateResponse(resp.Data)
	if err != nil {
		return nil, errors.Wrap(err, "invalid INITIALIZE UPDATE response")
	}

	rmacSupport := iur.keyInformation.iParam&0x20 == 0x20
	rencSupport := iur.keyInformation.iParam&0x60 == 0x60

	level := SecurityLevel{}

	switch config.CommandSecurityLevel {
	case CMAC:
		level.CMAC = true
	case CMACAndCDEC:
		level.CMAC = true
		level.CDEC = true
	}

	respSecurityLevel := configureResponseSecurityLevel(rmacSupport, rencSupport)

	switch respSecurityLevel {
	case None:
		break
	case RMAC:
		if !rmacSupport {
			return nil, errors.New("security level R-MAC requested but not supported")
		}

		level.RMAC = true
	case RMACAndRENC:
		if !rencSupport {
			return nil, errors.New("security level R-MAC and R-ENC requested but not supported")
		}

		level.RMAC = true
		level.RENC = true
	}

	session := &Session{
		keyProvider:         keyProvider,
		securityLevel:       level,
		keys:                sessionKeys{kvn: iur.keyInformation.version},
		channelID:           config.ChannelID,
		encryptionCounter:   [16]byte{},
		iv:                  [16]byte{},
		chainingValue:       [16]byte{},
		sequenceCounter:     iur.sequenceCounter,
		context:             append(config.HostChallenge[:], iur.cardChallenge[:]...),
		diversificationData: iur.keyDiversificationData[:],
		lock:                sync.Mutex{},
	}

	byteSize, err := session.keyProvider.KeyByteSize(session.keys.kvn)
	if err != nil {
		return nil, KeyDerivationError{Message: "did not receive size of keys", Cause: err}
	}

	if byteSize != 16 && byteSize != 24 && byteSize != 32 {
		return nil, KeyDerivationError{Message: fmt.Sprintf("invalid key byte size - must be 16, 24 or 32 bytes long, got %d", byteSize)}
	}

	// derive session keys
	err = session.deriveSENC(byteSize)
	if err != nil {
		return nil, err
	}

	err = session.deriveCMAC(byteSize)
	if err != nil {
		return nil, err
	}

	if level.RMAC {
		err = session.deriveRMAC(byteSize)
		if err != nil {
			return nil, err
		}
	}

	cc, err := session.calculateCryptogram(0x00)
	if err != nil {
		return nil, errors.Wrap(err, "calculate card cryptogram on host")
	}

	// compare cryptogram presented by the card with own cryptogram
	if !bytes.Equal(cc[:], iur.cardCryptogram[:]) {
		return nil, CardCryptogramError{Expected: cc, Received: iur.cardCryptogram[:]}
	}

	hc, err := session.calculateCryptogram(0x01)
	if err != nil {
		return nil, errors.Wrap(err, "calculate host cryptogram")
	}

	extAuthenticate, err := session.externalAuthenticate(hc)
	if err != nil {
		return nil, errors.Wrap(err, "generate EXTERNAL AUTHENTICATE command")
	}

	extAuthenticate.Cla = onLogicalChannel(session.channelID, extAuthenticate.Cla)

	resp, err = transmitter.Transmit(extAuthenticate)
	if err != nil {
		return nil, TransmitError{Command: extAuthenticate, Cause: err}
	}

	if !resp.IsSuccess() {
		return nil, NonSuccessResponseError{
			Command:  extAuthenticate,
			Response: resp,
		}
	}

	return session, nil
}

type initializeUpdateResponse struct {
	keyDiversificationData [10]byte       // key diversification Data is Data typically used by a backend system to derive the card static keys.
	keyInformation         keyInformation // key information includes the version Number and the Secure Channel Protocol identifier
	cardChallenge          [8]byte        // random number generated by the card
	cardCryptogram         [8]byte        // authentication cryptogram generated by the card
	sequenceCounter        []byte         // only present when SCP03 is configured for pseudo-random challenge generation.
}

type keyInformation struct {
	version byte
	scpID   byte
	iParam  byte
}

func parseInitializeUpdateResponse(b []byte) (*initializeUpdateResponse, error) {
	if len(b) < 29 || len(b) > 32 {
		return nil, fmt.Errorf("INITIALIZE UPDATE response must be 29 or 32 bytes long, got %d", len(b))
	}

	var (
		divData    [10]byte
		challenge  [8]byte
		cryptogram [8]byte
		counter    []byte
	)

	_ = copy(divData[:], b[:10])

	keyInfo := keyInformation{version: b[10], scpID: b[11], iParam: b[12]}

	if keyInfo.scpID != 0x03 {
		return nil, errors.Errorf("scp ID must be 03, got %d", keyInfo.scpID)
	}

	if keyInfo.iParam&0x10 == 0x10 {
		if len(b) != 32 {
			return nil, errors.Errorf("INITIALIZE UPDATE response must be 32 bytes long when pseudo-random card challenge is used, got %d", len(b))
		}

		counter = b[29:]
	}

	_ = copy(challenge[:], b[13:21])
	_ = copy(cryptogram[:], b[21:29])

	return &initializeUpdateResponse{
		keyDiversificationData: divData,
		keyInformation:         keyInfo,
		cardChallenge:          challenge,
		cardCryptogram:         cryptogram,
		sequenceCounter:        counter,
	}, nil
}

// Session is a SCP03 secure channel session.
type Session struct {
	keyProvider         SessionKeyProvider
	securityLevel       SecurityLevel
	keys                sessionKeys
	channelID           uint8
	encryptionCounter   [16]byte
	iv                  [16]byte
	chainingValue       [16]byte
	sequenceCounter     []byte
	context             []byte
	diversificationData []byte
	lock                sync.Mutex
}

type sessionKeys struct {
	kvn  uint8
	senc cipher.Block
	cmac cipher.Block
	rmac cipher.Block
}

func (session *Session) calculateCryptogram(constant byte) ([]byte, error) {
	cryptogram := make([]byte, 8)

	label := make([]byte, 12)

	label[11] = constant

	err := KDF(cryptogram, session.keys.cmac, label, session.context)
	if err != nil {
		return cryptogram, errors.Wrap(err, "calculate KDF counter for card cryptogram")
	}

	return cryptogram, nil
}

// MaximumCommandPayloadLength returns the maximum length of payload for the Data field of CAPDUs that are
// transmitted during the session. The length depends on the Session's SecurityLevel.
func (session *Session) MaximumCommandPayloadLength() int {
	d := 255

	if session.securityLevel.CMAC {
		d -= 8
		if session.securityLevel.CDEC {
			d -= 8
		}
	}

	return d
}

// Wrap applies operations (C-MAC, command encryption) depending on the SecurityLevel of the session to a apdu.Capdu and returns the resulting apdu.Capdu.
func (session *Session) Wrap(capdu apdu.Capdu) (apdu.Capdu, error) {
	session.lock.Lock()
	defer session.lock.Unlock()

	return session.wrapWithSecurityLevel(capdu, session.securityLevel)
}

func (session *Session) wrapWithSecurityLevel(capdu apdu.Capdu, level SecurityLevel) (apdu.Capdu, error) {
	var err error

	if level.CMAC {
		if level.CDEC {
			capdu, err = session.applyEncryption(capdu)
			if err != nil {
				return apdu.Capdu{}, errors.Wrap(err, "apply encryption on CAPDU")
			}
		}

		capdu, err = session.applyCMAC(capdu)
		if err != nil {
			return apdu.Capdu{}, errors.Wrap(err, "apply CMAC on CAPDU")
		}
	}

	return capdu, nil
}

var scp03ZeroIV = make([]byte, 16)

func (session *Session) applyEncryption(capdu apdu.Capdu) (apdu.Capdu, error) {
	// set sm bit
	if capdu.Cla&0x04 != 0x04 {
		capdu.Cla += 0x04
	}

	// increment encryption counter before encrypting, even though there is no data field
	session.incrementEncryptionCounter()

	if len(capdu.Data) == 0 {
		return capdu, nil
	}

	src := capdu.Data

	src, err := Pad80(src, 16, true)
	if err != nil {
		return apdu.Capdu{}, errors.Wrap(err, "pad data for encryption")
	}

	// encrypt encryption counter
	ivEncrypter := cipher.NewCBCEncrypter(session.keys.senc, scp03ZeroIV)
	ivEncrypter.CryptBlocks(session.iv[:], session.encryptionCounter[:])

	// encrypt data
	dataEncrypter := cipher.NewCBCEncrypter(session.keys.senc, session.iv[:])
	dataEncrypter.CryptBlocks(src, src)

	capdu.Data = src

	return capdu, nil
}

func (session *Session) incrementEncryptionCounter() {
	for i := len(session.encryptionCounter) - 1; i > 0; i-- {
		if i == 0 && session.encryptionCounter[i] == 0xFF {
			break
		}

		if session.encryptionCounter[i] != 0xFF {
			session.encryptionCounter[i]++

			break
		} else {
			session.encryptionCounter[i] = 0x00
		}
	}
}

func (session *Session) applyCMAC(capdu apdu.Capdu) (apdu.Capdu, error) {
	// check secure messaging bit
	if capdu.Cla&0x04 != 0x04 {
		capdu.Cla += 0x04
	}

	var lcWithCmac []byte

	if lengthCommand := len(capdu.Data) + 8; lengthCommand > apdu.MaxLenCommandDataStandard {
		lcWithCmac = make([]byte, 3)
		lcWithCmac[1] = (byte)(lengthCommand>>8) & 0xFF
		lcWithCmac[2] = (byte)(lengthCommand & 0xFF)
	} else {
		lcWithCmac = []byte{byte(lengthCommand)}
	}

	cmacInput := make([]byte, 0, len(session.chainingValue)+4+len(lcWithCmac)+len(capdu.Data))
	cmacInput = append(cmacInput, session.chainingValue[:]...)
	cmacInput = append(cmacInput, []byte{capdu.Cla, capdu.Ins, capdu.P1, capdu.P2}...)
	cmacInput = append(cmacInput, lcWithCmac...)
	cmacInput = append(cmacInput, capdu.Data...)

	cmacMac, err := cmac.NewWithTagSize(session.keys.cmac, session.keys.cmac.BlockSize())
	if err != nil {
		return apdu.Capdu{}, errors.Wrap(err, "create CMAC from S-MAC AES cipher")
	}

	_, err = cmacMac.Write(cmacInput)
	if err != nil {
		return apdu.Capdu{}, errors.Wrap(err, "update CMAC")
	}

	cm := cmacMac.Sum(nil)

	// add 8 most significant bytes of calculated value to data
	data := make([]byte, 0, len(capdu.Data)+8)
	data = append(data, capdu.Data...)
	data = append(data, cm[:8]...)

	capdu.Data = data

	copy(session.chainingValue[:], cm[:16])

	return capdu, nil
}

// RMACError results from a mismatch between the R-MAC calculated on host and the R-MAC received from the card.
type RMACError struct {
	Expected []byte // Expected R-MAC.
	Received []byte // Received R-MAC.
}

func (e RMACError) Error() string {
	return fmt.Sprintf("scp03: invalid R-MAC: expected: %02X received: %02X", e.Expected, e.Received)
}

// Unwrap applies operations (R-MAC, response decryption) depending on the SecurityLevel of the session to a apdu.Rapdu and returns the resulting apdu.Rapdu.
func (session *Session) Unwrap(rapdu apdu.Rapdu) (apdu.Rapdu, error) {
	session.lock.Lock()
	defer session.lock.Unlock()

	return session.unwrapWithSecurityLevel(rapdu, session.securityLevel)
}

func (session *Session) unwrapWithSecurityLevel(rapdu apdu.Rapdu, level SecurityLevel) (apdu.Rapdu, error) {
	var err error

	if level.RMAC {
		rapdu, err = session.applyRMAC(rapdu)
		if err != nil {
			return apdu.Rapdu{}, errors.Wrap(err, "could not apply RMAC on wrapped RAPDU")
		}

		if level.RENC {
			rapdu, err = session.applyRENC(rapdu)
			if err != nil {
				return apdu.Rapdu{}, errors.Wrap(err, "could not apply decryption on wrapped RAPDU")
			}
		}
	}

	return rapdu, nil
}

func (session *Session) applyRENC(rapdu apdu.Rapdu) (apdu.Rapdu, error) {
	if len(rapdu.Data) == 0 {
		return rapdu, nil
	}

	// before decryption, the most significant byte of the encryption counter shall be set to '80'
	respEncCounter := session.encryptionCounter
	respEncCounter[0] = 0x80

	iv := make([]byte, 16)

	ivEncrypter := cipher.NewCBCEncrypter(session.keys.senc, scp03ZeroIV)
	// store encrypted response encryption counter as IV
	ivEncrypter.CryptBlocks(iv, respEncCounter[:])

	dataDecrypter := cipher.NewCBCDecrypter(session.keys.senc, iv)

	decryptedData := make([]byte, len(rapdu.Data))
	dataDecrypter.CryptBlocks(decryptedData, rapdu.Data)

	// search for '80' which indicates start of padding
	offset := len(decryptedData) - 1
	for offset > 0 && decryptedData[offset] == 0x00 {
		offset--
	}

	if decryptedData[offset] != 0x80 {
		return apdu.Rapdu{}, errors.New("decrypted data is missing '80' tag for start of padding")
	}

	rapdu.Data = decryptedData[:offset]

	return rapdu, nil
}

func (session *Session) applyRMAC(rapdu apdu.Rapdu) (apdu.Rapdu, error) {
	if len(rapdu.Data) < 8 {
		return apdu.Rapdu{}, errors.New("RAPDU with R-MAC must be at least 8 bytes long")
	}

	payloadLen := len(rapdu.Data) - 8

	respRMAC := rapdu.Data[payloadLen:]

	// calculate the r-mac value
	rmacInput := make([]byte, 0, len(session.chainingValue)+payloadLen+2)
	rmacInput = append(rmacInput, session.chainingValue[:]...)
	rmacInput = append(rmacInput, rapdu.Data[:payloadLen]...)
	rmacInput = append(rmacInput, rapdu.SW1)
	rmacInput = append(rmacInput, rapdu.SW2)

	// calculate the mac
	rmac, err := cmac.NewWithTagSize(session.keys.rmac, session.keys.rmac.BlockSize())
	if err != nil {
		return apdu.Rapdu{}, errors.Wrap(err, "create CMAC from R-MAC AES cipher")
	}

	_, err = rmac.Write(rmacInput)
	if err != nil {
		return apdu.Rapdu{}, errors.Wrap(err, "update CMAC with input")
	}

	// calculate and pick 8 most significant bytes
	calculatedRMAC := rmac.Sum(nil)[:8]

	if !bytes.Equal(calculatedRMAC, respRMAC) {
		return apdu.Rapdu{}, RMACError{
			Expected: calculatedRMAC,
			Received: respRMAC,
		}
	}

	rapdu.Data = rapdu.Data[:len(rapdu.Data)-8]

	return rapdu, nil
}

func deriveSessionKey(dst []byte, keyID byte, kvn byte, diversificationData []byte, provider SessionKeyProvider, context []byte, derivationConstant byte) error {
	label := make([]byte, 12)
	label[11] = derivationConstant

	err := provider.ProvideSessionKey(dst, label, context, keyID, kvn, diversificationData)
	if err != nil {
		return KeyDerivationError{Message: "session key not provided", Cause: err}
	}

	return nil
}

const (
	// KeyIDEnc is the ID of the Secure Channel encryption key (ENC).
	KeyIDEnc byte = 0x01
	// KeyIDMac is the ID of the Secure Channel Message authentication code key (MAC).
	KeyIDMac byte = 0x02
	// KeyIDDek is the ID of the Data encryption key (DEK).
	KeyIDDek byte = 0x03
)

func (session *Session) deriveSENC(byteSize int) error {
	derivedKey := make([]byte, byteSize)

	err := deriveSessionKey(derivedKey, KeyIDEnc, session.keys.kvn, session.diversificationData, session.keyProvider, session.context, 0x04)
	if err != nil {
		return errors.Wrap(err, "derive S-ENC")
	}

	ac, err := aes.NewCipher(derivedKey)
	if err != nil {
		return errors.Wrap(err, "create AES cipher from S-ENC")
	}

	session.keys.senc = ac

	return nil
}

func (session *Session) deriveCMAC(byteSize int) error {
	derivedKey := make([]byte, byteSize)

	err := deriveSessionKey(derivedKey, KeyIDMac, session.keys.kvn, session.diversificationData, session.keyProvider, session.context, 0x06)
	if err != nil {
		return errors.Wrap(err, "derive C-MAC")
	}

	ac, err := aes.NewCipher(derivedKey)
	if err != nil {
		return errors.Wrap(err, "create AES cipher from C-MAC")
	}

	session.keys.cmac = ac

	return nil
}

func (session *Session) deriveRMAC(byteSize int) error {
	derivedKey := make([]byte, byteSize)

	err := deriveSessionKey(derivedKey, KeyIDMac, session.keys.kvn, session.diversificationData, session.keyProvider, session.context, 0x07)
	if err != nil {
		return errors.Wrap(err, "derive R-MAC")
	}

	ac, err := aes.NewCipher(derivedKey)
	if err != nil {
		return errors.Wrap(err, "create AES cipher from R-MAC")
	}

	session.keys.rmac = ac

	return nil
}

func (session *Session) externalAuthenticate(hc []byte) (apdu.Capdu, error) {
	ea := apdu.Capdu{
		Cla:  0x84,
		Ins:  0x82,
		P1:   session.securityLevel.Byte(),
		P2:   0x00,
		Data: hc,
		Ne:   apdu.MaxLenResponseDataStandard,
	}

	// wrap the external authenticate commando only with cmac and ignore other security options
	cmd, err := session.wrapWithSecurityLevel(ea, SecurityLevel{CMAC: true})
	if err != nil {
		return apdu.Capdu{}, errors.Wrap(err, "wrap EXTERNAL AUTHENTICATE command")
	}

	return cmd, nil
}

// BeginRMACSession starts a R-MAC session. Data is used to specify the Data field of the BEGIN R-MAC SESSION command.
// This function calls SessionKeyProvider.Encrypt on the encrypter for the MAC key, that was provided when creating Session, in order to derive the R-MAC key
// and calls Transmitter.Transmit to transmit the BEGIN R-MAC SESSION CAPDU and receive the RAPDU.
func (session *Session) BeginRMACSession(responseSecurityLevel ResponseSecurityLevel, transmitter Transmitter, data []byte) error {
	session.lock.Lock()
	defer session.lock.Unlock()

	if session.keys.rmac == nil {
		err := session.deriveRMAC(session.keys.cmac.BlockSize())
		if err != nil {
			return errors.Wrap(err, "derive R-MAC")
		}
	}

	p1 := byte(0x00)

	switch responseSecurityLevel {
	case None:
		return errors.New("response security level must not be 'None''")
	case RMAC:
		p1 += 0x10
	case RMACAndRENC:
		p1 += 0x30
	}

	beginCmd := apdu.Capdu{
		Cla:  0x80,
		Ins:  0x7A,
		P1:   p1,
		P2:   0x01,
		Data: data,
		Ne:   0,
	}

	wrappedBeginCmd, err := session.wrapWithSecurityLevel(beginCmd, session.securityLevel)
	if err != nil {
		return errors.Wrap(err, "wrap BEGIN R-MAC SESSION command")
	}

	wrappedBeginCmd.Cla = onLogicalChannel(session.channelID, wrappedBeginCmd.Cla)

	resp, err := transmitter.Transmit(wrappedBeginCmd)
	if err != nil {
		return TransmitError{Command: beginCmd, Cause: err}
	}

	unwrapped, err := session.unwrapWithSecurityLevel(resp, session.securityLevel)
	if err != nil {
		return errors.Wrap(err, "unwrap BEGIN R-MAC Session response")
	}

	if !unwrapped.IsSuccess() {
		return NonSuccessResponseError{
			Command:  wrappedBeginCmd,
			Response: unwrapped,
		}
	}

	switch responseSecurityLevel {
	case RMAC:
		session.securityLevel.RMAC = true
	case RMACAndRENC:
		session.securityLevel.RMAC = true
		session.securityLevel.RENC = true
	}

	return nil
}

//	EndRMACSession terminates a Secure Channel Session for APDU response Message integrity or
//	to retrieve the current R-MAC without ending the R-MAC SCP02Session. The END R-MAC SESSION command may be issued to the
//	card at any time during an R-MAC session.
func (session *Session) EndRMACSession(transmitter Transmitter) (apdu.Rapdu, error) {
	session.lock.Lock()
	defer session.lock.Unlock()

	endCmd := apdu.Capdu{
		Cla:  0x80,
		Ins:  0x78,
		P1:   0x00,
		P2:   0x03,
		Data: nil,
		Ne:   apdu.MaxLenResponseDataStandard,
	}

	wrappedEndCmd, err := session.wrapWithSecurityLevel(endCmd, session.securityLevel)
	if err != nil {
		return apdu.Rapdu{}, errors.Wrap(err, "wrap END R-MAC SESSION command")
	}

	resp, err := transmitter.Transmit(wrappedEndCmd)
	if err != nil {
		return apdu.Rapdu{}, TransmitError{Command: wrappedEndCmd, Cause: err}
	}

	unwrapped, err := session.unwrapWithSecurityLevel(resp, session.securityLevel)
	if err != nil {
		return apdu.Rapdu{}, errors.Wrap(err, "unwrap BEGIN R-MAC Session response")
	}

	if !unwrapped.IsSuccess() {
		return apdu.Rapdu{}, NonSuccessResponseError{
			Command:  wrappedEndCmd,
			Response: unwrapped,
		}
	}

	session.securityLevel.RMAC = false
	session.securityLevel.RENC = false

	return unwrapped, nil
}

// SecurityLevel represents the security level options for SCP03.
type SecurityLevel struct {
	CDEC bool // command decryption
	CMAC bool // command Message authentication code
	RMAC bool // response Message authentication code
	RENC bool // response encryption
}

// Byte encodes SecurityLevel on a byte.
func (level SecurityLevel) Byte() byte {
	b := byte(0x00)

	if level.CMAC {
		b += 0x01
	}

	if level.CDEC {
		b += 0x02
	}

	if level.RMAC {
		b += 0x10
	}

	if level.RENC {
		b += 0x20
	}

	return b
}

func onLogicalChannel(channelID, cla byte) byte {
	if channelID <= 3 {
		return cla | channelID
	}

	if cla&0x40 != 0x40 {
		cla += 0x40
	}

	if channelID > 19 {
		channelID = 19
	}

	channelID -= 4

	return cla | (channelID & 0x0F)
}

const prfLen = uint16(128)

// KDF implements a version of KDF in counter mode as specified in NIST SP 800-108.
// The PRF used in the KDF shall is CMAC as specified in NIST 800-38B] with 16-byte output length.
// The KDF takes an AES cipher, a label, a derivation context and the required number of output bits.
func KDF(dst []byte, aesCipher cipher.Block, label []byte, context []byte) error {
	if len(dst) == 0 || len(dst)%8 != 0 || len(dst) > 32 {
		return errors.Errorf("length of dst must be a multiple of 8 and not greater than 32 bytes, got %d", len(dst))
	}

	if len(label) != 12 {
		return errors.Errorf("length of label must be 12 bytes, got %d", len(label))
	}

	if len(context) != 16 {
		return errors.Errorf("length of context must be 16 bytes, got %d", len(context))
	}

	bits := uint16(len(dst) * 8)

	rounds := uint8(bits / prfLen)
	if bits%prfLen != 0 {
		rounds++
	}

	// label + separator + counter + context
	input := make([]byte, 0, len(label)+4+len(context))
	input = append(input, label...)
	input = append(input, 0x00)
	input = append(input, uint8(bits>>8), uint8(bits&0xFF))
	input = append(input, 0x00)
	input = append(input, context...)

	var result []byte

	for i := uint8(1); i <= rounds; i++ {
		// update the counter
		input[15] = i

		cmacMac, err := cmac.NewWithTagSize(aesCipher, 16)
		if err != nil {
			return errors.Wrap(err, "create CMAC from cipher")
		}

		cmacMac.Write(input)
		part := cmacMac.Sum(nil)

		if uint16(len(part)*8) != prfLen {
			return errors.Errorf("PRF length mis-match (%d vs %d)", len(part)*8, prfLen)
		}

		result = append(result, part...)
	}

	copy(dst, result)

	return nil
}

// Pad80 takes bytes and a block size (must be a multiple of 8) and appends '80' and zero bytes until
// the length reaches a multiple of the block size and returns the padded bytes.
// If force is false, the padding will only be applied, if the length of bytes is not a multiple of the block size.
// If force is true, the padding will be applied anyways.
func Pad80(b []byte, blockSize int, force bool) ([]byte, error) {
	if blockSize%8 != 0 {
		return nil, errors.New("block size must be a multiple of 8")
	}

	rest := len(b) % blockSize
	if rest != 0 || force {
		padded := make([]byte, len(b)+blockSize-rest)
		copy(padded, b)
		padded[len(b)] = 0x80

		return padded, nil
	}

	return b, nil
}
