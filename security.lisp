
;;;; NTLM Authentication library

;;; 
;;; Provides functions and data structures to handle the NTLM authentication protocol,
;;; commonly used by Microsoft Windows platforms.
;;; See http://msdn.microsoft.com/en-gb/library/cc236621.aspx for more information.
;;;
;;; Copyright (C) Frank James, July 2014
;;;



(in-package :ntlm)

;; Code taken from http://exampledepot.8waytrips.com/egs/javax.crypto/MakeDes.html"
(defun make-des-key (7-bytes)
  "Convert a 7-byte key (56-bit) into an 8-byte key (with parity bits set) suitable for use with Ironclad DES algorithm."
  (labels ((at (i)
             (elt 7-bytes i)))
    (let ((key (make-array 8 :initial-element 0 :element-type '(unsigned-byte 8)))
          (result-ix 1)
          (bit-count 0))
      (dotimes (i 56)
        ;; Get the bit at bit position i
        ;; If set, set the corresponding bit in the result
        ;; (in[6-i/8]&(1<<(i%8))) > 0;
        (when (> (logand (at (- 6 (truncate i 8)))
                         (ash 1 (mod i 8)))
                 0)
          ;; result[7-resultIx/8] |= (1<<(resultIx%8))&0xFF;
          ;; bitCount++;
          (setf (elt key (- 7 (truncate result-ix 8)))
                (logior (elt key (- 7 (truncate result-ix 8)))
                        (logand (ash 1 (mod result-ix 8))
                                #xff))
                bit-count 
                (1+ bit-count)))

        ;; Set the parity bit after every 7 bits
        (when (zerop (mod (1+ i) 7))
          (when (zerop (mod bit-count 2))
            ;; Set low-order bit (parity bit) if bit count is even
            ;; result[7-resultIx/8] |= 1;
            (setf (elt key (- 7 (truncate result-ix 8)))
                  (logior (elt key (- 7 (truncate result-ix 8)))
                          1)))
          (incf result-ix)
          (setf bit-count 0))

        (incf result-ix))

      key)))

(defun des (key data)
  "Tested and works"
  (let ((cipher (ironclad:make-cipher :des :key (make-des-key key):mode :ecb))
        (msg (make-array 8 :element-type '(unsigned-byte 8))))
    (ironclad:encrypt cipher data msg)
    msg))

(defun md4 (msg)
  (declare ((vector (unsigned-byte 8)) msg))
  (ironclad:digest-sequence :md4 msg))
    
(defun md5 (msg)
  (declare ((vector (unsigned-byte 8)) msg))
  (ironclad:digest-sequence :md5 msg))

(defun crc32 (msg)
  (declare ((vector (unsigned-byte 8)) msg))
  (ironclad:digest-sequence :crc32 msg))

(defun rc4k (key data)
  "Tested and works"
  (let ((cipher (ironclad:make-cipher :arcfour :key key :mode :stream))
        (msg (make-array (length data) :element-type '(unsigned-byte 8))))
    (ironclad:encrypt cipher data msg)
    msg))

(defun rc4-init (key)
  (ironclad:make-cipher :arcfour :key key :mode :stream))

(defun rc4 (cipher data)
  (let ((msg (make-array (length data) :element-type '(unsigned-byte 8))))
    (ironclad:encrypt cipher data msg)
    msg))

(defun hmac-md5 (key data)
  (let ((hmac (ironclad:make-hmac key :md5)))
    (ironclad:update-hmac hmac data)
    (ironclad:hmac-digest hmac)))

;; 8-byte data item and 16-byte key
(defun desl (key data)
  (usb8 (des (subseq key 0 7) data)
        (des (subseq key 7 14) data)
        (des (pad (subseq key 14) 7) data)))

;; 3.3.1 NTLM v1 Authentication http://msdn.microsoft.com/en-us/library/cc236699.aspx
(defconstant* +lmowf-v1-data+ (pack "KGS!@#$%" :string))
(defun lmowf-v1 (string)
  "Tested and works."
  ;; NOTE: if the string is 14 or more chars, then replace with 0 
  (let ((bytes (pad (pack (if (< (length string) 14)
                              (string-upcase string)
                              "")
                          :string) 
                    14)))
    (usb8 (des (subseq bytes 0 7) +lmowf-v1-data+) 
          (des (subseq bytes 7 14) +lmowf-v1-data+))))
                      
(defun ntowf-v1 (string)
  "This works correctly"
  (md4 (pack string :wstring)))

(defun password-md4 (password)
  (md4 (pack password :wstring)))

;; 3.3.2 NTLM v2 Authentication http://msdn.microsoft.com/en-us/library/cc236700.aspx
(defun ntowf-v2 (username domain pword-md4)
  "Tested and works"
  (hmac-md5 pword-md4
	    (usb8 (pack (concatenate 'string (string-upcase username) domain)
			:wstring))))
            
(defun lmowf-v2 (username domain pword-md4)
  "Tested and works"
  (ntowf-v2 username domain pword-md4))

;; 3.4.5.1 KXKEY http://msdn.microsoft.com/en-us/library/cc236710.aspx
(defun key-exchange-key (session-base-key lm-response server-challenge lmowf
                         &key negotiate-lm-key request-non-nt-session-key negotiate-extended-sessionsecurity)
  (cond
    (negotiate-extended-sessionsecurity
     (hmac-md5 session-base-key
	       (usb8 server-challenge 
                     (subseq lm-response 0 8))))
    (negotiate-lm-key 
     (usb8 (des (subseq lmowf 0 7) (subseq lm-response 0 8))
           (des (usb8 (subseq lmowf 7 8)
		      #(#xBD #xBD #xBD #xBD #xBD #xBD))
                (subseq lm-response 0 8))))
    (request-non-nt-session-key 
     (pad (subseq lmowf 0 8) 16))
    (t 
     session-base-key)))

;; 3.3.1 NTLM v1 Authentication http://msdn.microsoft.com/en-us/library/cc236699.aspx                  
(defun lm-response-v1 (lmowf server-challenge)
  (desl lmowf server-challenge))

(defun nt-response-v1 (ntowf server-challenge)
  (desl ntowf server-challenge))

;; use these when there is a client challenge
(defun nt-response-v1* (ntowf server-challenge client-challenge &key negotiate-extended-sessionsecurity)
  (cond
    (negotiate-extended-sessionsecurity
     (desl ntowf 
	   (subseq (md5 (usb8 server-challenge client-challenge)) 0 8)))
    (t (nt-response-v1 ntowf server-challenge))))

(defun lm-response-v1* (lmowf ntowf server-challenge client-challenge 
		     &key negotiate-extended-sessionsecurity negotiate-lm-key)
  (cond
    (negotiate-extended-sessionsecurity    
     (usb8 client-challenge (make-array 16 :element-type '(unsigned-byte 8))))
    (negotiate-lm-key 
     (lm-response-v1 lmowf server-challenge))
    (t (nt-response-v1* ntowf server-challenge client-challenge 
		     :negotiate-extended-sessionsecurity negotiate-extended-sessionsecurity))))

(defun session-base-key-v1 (password)
  (md4 (ntowf-v1 password)))

;; 3.3.2 NTLM v2 Authentication http://msdn.microsoft.com/en-us/library/cc236700.aspx
(defun make-temp (time client-challenge target-info)
  (usb8 '(1 1 0 0 0 0 0 0) 
	(pack time :uint64)
	client-challenge 
	'(0 0 0 0) 
    (if (arrayp target-info)
        target-info
        (apply #'usb8 (mapcar #'pack-av-pair target-info)))
	'(0 0 0 0)))

(defun temp-list (buffer)
  (list (cons :timestamp (unpack (subseq* buffer 8 8) :uint64))
        (cons :client-challenge (subseq* buffer 16 8))
        (cons :target-info (target-info-list 
                            (unpack-target-info (subseq buffer 28))))))
        
;; 3.3.2 NTLM v2 Authentication http://msdn.microsoft.com/en-us/library/cc236700.aspx
(defun session-base-key-v2 (ntowfv2 server-challenge temp)
  (hmac-md5 ntowfv2
            (hmac-md5 ntowfv2 (usb8 server-challenge temp))))

(defun lm-response-v2 (lmowf server-challenge client-challenge)
  (usb8 (hmac-md5 lmowf 
		  (usb8 server-challenge client-challenge))
	client-challenge))

(defun nt-response-v2 (ntowfv2 server-challenge temp) 
  (usb8 (hmac-md5 ntowfv2 (usb8 server-challenge temp))
        temp))

(defun nt-response-v2-list (buffer)
  (list (cons :nt-response (subseq buffer 0 16))
        (cons :temp (temp-list (subseq buffer 16)))
        (cons :temp-buffer (subseq buffer 16))))


;; 3.4.5.2 SIGNKEY http://msdn.microsoft.com/en-us/library/cc236711.aspx
(defun sign-key (exported-session-key magic-constant &key negotiate-extended-sessionsecurity)
  (cond
    (negotiate-extended-sessionsecurity
     (md5 (usb8 exported-session-key magic-constant)))
    (t nil)))

;; 3.4.5.3 SEALKEY http://msdn.microsoft.com/en-us/library/cc236712.aspx
(defun seal-key (exported-session-key magic-constant &key negotiate-extended-sessionsecurity 
                               negotiate-lm-key negotiate-datagram negotiate-56
                               negotiate-128)
  (cond
    (negotiate-extended-sessionsecurity
     (let ((skey (cond
                   (negotiate-128 exported-session-key)
                   (negotiate-56 (subseq exported-session-key 0 7))
                   (t (subseq exported-session-key 0 5)))))
       (md5 (usb8 skey magic-constant))))
    ((or negotiate-lm-key negotiate-datagram)
     (if negotiate-56
         (usb8 (subseq exported-session-key 0 7) #(#xa0))
         (usb8 (subseq exported-session-key 0 5) #(#xe5 #x38 #xb0))))
    (t exported-session-key)))

;; 3.4.4.1 Without Extended Session Security http://msdn.microsoft.com/en-us/library/cc422953.aspx
;; 3.4.4.2 With Extended Session Security http://msdn.microsoft.com/en-us/library/cc422954.aspx
(defun mac (cipher msg signing-key seqnum 
            &key (random-pad 0) negotiate-extended-sessionsecurity negotiate-key-exch)
    (cond
      (negotiate-extended-sessionsecurity
       (let ((chksum (subseq (hmac-md5 signing-key (usb8 (pack seqnum :uint32) msg)) 0 8)))             
         (values (pack-message-signature (if negotiate-key-exch
                                             (rc4 cipher chksum)
                                             chksum)
                                         seqnum)
                 (1+ seqnum))))
      (t 
       (let ((rpad (rc4 cipher (pack random-pad :uint32)))
             (chksum (rc4 cipher (crc32 msg)))
             (sno (rc4 cipher (usb8* 0 0 0 0))))
         (declare (ignore rpad))
         (values (pack-message-signature chksum (logxor (unpack sno :uint32) seqnum))
                 (1+ seqnum))))))
    
;; 3.1.5.1.2 Client Receives a CHALLENGE_MESSAGE from the Server 
;; http://msdn.microsoft.com/en-us/library/cc236676.aspx
(defun encrypted-session-key (key-exchange-key exported-session-key &key (negotiate-key-exch t))
  (if negotiate-key-exch
      (rc4k key-exchange-key exported-session-key)
      (make-array 16 :initial-element 0 :element-type '(unsigned-byte 8))))

;; 3.1.5.1.2 http://msdn.microsoft.com/en-us/library/cc236676.aspx
(defun mic (exported-session-key negotiate-message challenge-message authenticate-message )
  (hmac-md5 exported-session-key
            (usb8 negotiate-message challenge-message authenticate-message)))


(defun nonce (n)
  (make-array n
              :element-type '(unsigned-byte 8)
              :initial-contents (loop for i below n collect (random 256))))

(defun client-challenge ()
  (nonce 8))

(defun server-challenge ()
  (nonce 8))

;; 3.1.5.1.2 Client Receives a CHALLENGE_MESSAGE from the Server 
;; http://msdn.microsoft.com/en-us/library/cc236676.aspx
(defun exported-session-key (&key key-exchange-key negotiate-key-exch)
  (cond
    (negotiate-key-exch (nonce 16))
    (key-exchange-key key-exchange-key)
    (t (error "Must provide a key-exchange-key if not using :NEGOTIATE-KEY-EXCH"))))


(defun channel-bindings (channel-bindings-unhashed)
  (md5 channel-bindings-unhashed))


