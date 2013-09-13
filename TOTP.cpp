// OpenAuthentication Time-based One-time Password Algorithm (RFC 6238)
// Arduino Library
//
// Luca Dentella (http://www.lucadentella.it)

#include "TOTP.h"
#include "sha1.h"

// Init the library with the private key and its length
TOTP::TOTP(uint8_t* hmacKey, int keyLength) {

	_hmacKey = hmacKey;
	_keyLength = keyLength;
};

// Generate a code, using the timestamp provided
// for the complete description of the algorithm see
// http://tools.ietf.org/html/rfc4226#section-5.3
char* TOTP::getCode(long timeStamp) {

	// STEP 0, number of steps (one every 30 seconds) from the Epoch
	_timeStep = timeStamp / 30;
	
	// STEP 0, map the number of steps in a 8-bytes array (counter value)
	_byteArray[0] = 0x00;
	_byteArray[1] = 0x00;
	_byteArray[2] = 0x00;
	_byteArray[3] = 0x00;
	_byteArray[4] = (int)((_timeStep >> 24) & 0xFF);
	_byteArray[5] = (int)((_timeStep >> 16) & 0xFF);
	_byteArray[6] = (int)((_timeStep >> 8) & 0XFF);
	_byteArray[7] = (int)((_timeStep & 0XFF));
	
	// STEP 1, get the HMAC-SHA1 hash from counter and key
	Sha1.initHmac(_hmacKey, _keyLength);
	Sha1.write(_byteArray, 8);
	_hash = Sha1.resultHmac();
	
	// STEP 2, apply dynamic truncation to obtain a 4-bytes string
	_offset = _hash[20 - 1] & 0xF; 
	_truncatedHash = 0;
	for (int j = 0; j < 4; ++j) {
		_truncatedHash <<= 8;
		_truncatedHash  |= _hash[_offset + j];
	}

	// STEP 3, compute the OTP value
	_truncatedHash &= 0x7FFFFFFF;
	_truncatedHash %= 1000000;
	
	// convert the value in string, with heading zeroes
	sprintf(_code, "%06ld", _truncatedHash);
	return _code;
}
