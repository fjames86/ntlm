

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

(defun rc4 (key data)
  "Tested and works"
  (let ((cipher (ironclad:make-cipher :arcfour :key key :mode :stream))
        (msg (make-array (length data) :element-type '(unsigned-byte 8))))
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
  "Tested and works"
  (let ((bytes (pad (pack (string-upcase string) :string) 14)))
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
(defun make-temp (time client-challenge computer-name domain-name)
  (usb8 '(1 1 0 0 0 0 0 0) 
	(pack time :uint64)
	client-challenge 
	'(0 0 0 0) 
	(apply #'usb8
	       (mapcar #'pack-av-pair 
		       (make-target-info 
			:domain-name domain-name
			:computer-name computer-name)))		
	'(0 0 0 0)))p

;; 3.3.2 NTLM v2 Authentication http://msdn.microsoft.com/en-us/library/cc236700.aspx
(defun session-base-key-v2 (ntowfv2 server-challenge client-challenge computer-name domain-name time)
  (let ((temp (make-temp time client-challenge computer-name domain-name)))
    (hmac-md5 ntowfv2
	      (hmac-md5 ntowfv2 (usb8 server-challenge temp)))))

(defun lm-response-v2 (lmowf server-challenge client-challenge)
  (usb8 (hmac-md5 lmowf 
		  (usb8 server-challenge client-challenge))
	client-challenge))

(defun nt-response-v2 (ntowfv2 server-challenge client-challenge computer-name domain-name time)
  (let ((temp (make-temp time client-challenge computer-name domain-name)))
    (usb8 (hmac-md5 ntowfv2 (usb8 server-challenge temp))
	  temp)))

		  

;; http://msdn.microsoft.com/en-us/library/cc236711.aspx
(defun sign-key (session-key magic &key negotiate-extended-sessionsecurity)
  (cond
    (negotiate-extended-sessionsecurity
     (md5 (usb8 session-key magic)))
    (t nil)))

;; http://msdn.microsoft.com/en-us/library/cc236712.aspx
(defun seal-key (session-key magic &key negotiate-extended-sessionsecurity 
                               negotiate-lm-key negotiate-datagram negotiate-56
                               negotiate-128)
  (cond
    (negotiate-extended-sessionsecurity
     (let ((skey (cond
                   (negotiate-128 session-key)
                   (negotiate-56 (subseq session-key 0 7))
                   (t (subseq session-key 0 5)))))
       (md5 (usb8 skey magic))))
    ((or negotiate-lm-key negotiate-datagram)
     (if negotiate-56
         (usb8 (subseq session-key 0 7) #(#xa0))
         (usb8 (subseq session-key 0 5) #(#xe5 #x38 #xb0))))
    (t session-key)))

;; untested....
(defun mac (msg sealing-key seqno &key (random-pad 0))
  (let ((chksum (rc4 sealing-key (crc32 msg)))
        (rpad (rc4 sealing-key (pack random-pad :uint32)))
        (sno (unpack (rc4 sealing-key (pack 0 :uint32))
		     :uint32)))
    (pack-message-signature chksum (1+ (logxor sno seqno)) rpad)))
    
(defun encrypted-session-key (key-exchange-key session-key)
  (rc4 key-exchange-key session-key))
