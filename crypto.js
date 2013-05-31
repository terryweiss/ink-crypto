"use strict";
/**
 * @fileOverview The sole purpose of this module is to surface Paul Johnston's cryptography libraries and the AES
 *               encryption library from a single, module-friendly place. This module exposes the most commonly used
 *               features of paj's library ({@link module:ink/crypto/sha1} and {@link module:ink/crypto/md5}) and the
 *               AES encryption library ({@link module:ink/crypto/AES}). Your basic guidance for using these is that
 *               sha1 and md5 are for one way encryption. AES can be used for two-way encryption.
 * @license MIT
 * @copyright Copyright &copy; 2009-2012 Uncommon Individual Foundation. All rights reserved.
 * @see http://pajhome.org.uk/crypt/md5/
 * @see http://pajhome.org.uk/crypt/sha1/
 * @see http://www.movable-type.co.uk/scripts/aes.html
 * @module ink/crypto
 * @borrows module:ink/crypto/md5.md5 as md5
 * @borrows module:ink/crypto/sha1.sha1 as sha1
 * @borrows module:ink/crypto/AES.encrypt as AES.encrypt
 * @borrows module:ink/crypto/AES.decrypt as AES.decrypt
 * @requires ink/ink
 * @requires ink/crypto/md5
 * @requires ink/crypto/sha1
 * @requires ink/crypto/AES
 */

var sys = require( "lodash" );

sys.extend( exports, require( "./crypto/md5" ), require( "./crypto/sha1" ) );
exports.AES = require( "./crypto/AES" );
