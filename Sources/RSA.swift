//
//  RSA.swift
//  Cryptor
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.
//

import Foundation

#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
	import CommonCrypto
	import Security
    import OpenSSL
#elseif os(Linux)
	import OpenSSL
#endif



///
/// RSA Handling: Implements a series of Class Level RSA Helper Functions.
///
public class RSA {
    
    private let algorithm: Algorithm
    private let key: UnsafeMutablePointer<UInt8>
    private let keySize: Int32
	
	// MARK: Enums
	
//	#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
    
    /// The RSA algorithm to use.
    public enum Algorithm {
        case md2
        case md4
        case md5
        case sha1
        case sha224
        case sha256
        case sha384
        case sha512
        
        
        /// OpenSSL equivalent.
        var nid: Int32 {
            switch self {
            case .md2:
                return NID_md2
            case .md4:
                return NID_md4
            case .md5:
                return NID_md5
            case .sha1:
                return NID_sha1
            case .sha224:
                return NID_sha224
            case .sha256:
                return NID_sha256
            case .sha384:
                return NID_sha384
            case .sha512:
                return NID_sha512
            }
        }
        
        /// `Digest` equivalent.
        var digest: Digest.Algorithm {
            switch self {
            case .md2:
                return .md2
            case .md4:
                return .md4
            case .md5:
                return .md5
            case .sha1:
                return .sha1
            case .sha224:
                return .sha224
            case .sha256:
                return .sha256
            case .sha384:
                return .sha384
            case .sha512:
                return .sha512
            }
        }
    }

		/// The RSA Algorithm to use.
//		public enum RSAAlgorithm: Int {
//			
//			case none
//			case pkcs1
//			case md2
//			case md5
//			case sha1
//		
//			/// Algorithm specific padding.
//			public var padding: SecPadding {
//				
//				switch self {
//					
//				case .none:
//					return .none
//				case .pkcs1:
//					return .PKCS1
//				case .md2:
//					return .PKCS1MD2
//				case .md5:
//					return .PKCS1MD5
//				case .sha1:
//					return .PKCS1SHA1
//				}
//			}
//		}

    
    /// Initializes a new `RSA` instance for signing.
    ///
    /// - parameter key:       The RSA private key, in PEM format.
    /// - parameter algorithm: The digest algorithm to use for signing.
    public init(key: Data, algorithm: Algorithm) {
        self.algorithm = algorithm
        self.key = UnsafeMutablePointer<UInt8>.allocate(capacity: key.count)
        key.copyBytes(to: self.key, count: key.count)
        self.keySize = Int32(key.count)
    }
    
    /// Signs the given data using the receiver's kay and digest algorithm.
    ///
    /// - parameter data: The data to sign.
    ///
    /// - returns: The signed data.
    public func sign(_ data: Data) -> Data? {
        // Generate hash
        let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
        data.copyBytes(to: ptr, count: data.count)
        guard let digest = Digest(using: algorithm.digest).update(from: ptr, byteCount: data.count) else {
            return nil
        }
        var digestBytes = digest.final()
        let keyBuf = BIO_new_mem_buf(key, keySize)
        // This can fail for invalid private keys, so we check here
        guard let rsa = PEM_read_bio_RSAPrivateKey(keyBuf, nil, nil, nil) else {
            return nil
        }
        let rsaSize = Int(RSA_size(rsa))
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: rsaSize)
        var len: UInt32 = 0
        let result = RSA_sign(algorithm.nid, &digestBytes, UInt32(digestBytes.count), buffer, &len, rsa)
        guard result != 0 else {
            return nil
        }
        return Data(bytes: buffer, count: rsaSize)
    }
    
    /// Signs the given string using the receiver's private key and digest algorithm.
    ///
    /// - parameter string:   The string to sign.
    /// - parameter encoding: The string's encoding.
    ///
    /// - returns: The signed data.
    public func sign(_ string: String, encoding: String.Encoding = .utf8) -> Data? {
        guard let data: Data = string.data(using: encoding) else {
            return nil
        }
        return sign(data)
    }
    
    
	
//	#elseif os(Linux)

	
//	#endif
}
