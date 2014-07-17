

;;;; NTLM Authentication library

;;; 
;;; Provides functions and data structures to handle the NTLM authentication protocol,
;;; commonly used by Microsoft Windows platforms.
;;; See http://msdn.microsoft.com/en-gb/library/cc236621.aspx for more information.
;;;
;;; Copyright (C) Frank James, July 2014
;;;







(in-package :ntlm)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Some utilities 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; we define some stringy constants so can't use the vanilla defconstant
(defmacro defconstant* (name value &optional doc)
  `(defconstant ,name (if (boundp ',name) (symbol-value ',name) ,value)
     ,@(when doc (list doc))))

(defmacro dolist* ((lambda-list list) &body body)
  "Map over a destructured list"
  (let ((gvar (gensym)))
    `(dolist (,gvar ,list)
       (destructuring-bind ,lambda-list ,gvar ,@body))))

(defun subseq* (sequence start &optional len)
  (subseq sequence start (when len (+ start len))))

(defun pad (array len)
  (let* ((l (length array))
         (arr (make-array (max len l) :initial-element 0 :element-type '(unsigned-byte 8))))
    (dotimes (i (length arr))
      (when (< i l)
        (setf (elt arr i) (elt array i))))
    arr))
          
(defun substr (string start &optional end)
  (let ((len (length string)))
    (if (> start len)
        ""
        (subseq string start (when end (max end len))))))

(defun split-powers-2 (num)
  (do ((i 0 (1+ i))
       (n nil))
      ((>= i 32) n)
    (let ((p (ash 1 i)))
      (unless (zerop (logand num p))
        (push i n)
        (setf num (logand num (lognot p)))))))

(defun hd (data)
  "Hexdump output"
  (let ((lbuff (make-array 16))
        (len (length data)))
    (labels ((pline (lbuff count)
               (dotimes (i count)
                 (format t " ~2,'0X" (svref lbuff i)))
               (dotimes (i (- 16 count))
                 (format t "   "))

               (format t " | ")
               (dotimes (i count)
                 (let ((char (code-char (svref lbuff i))))
                   (format t "~C" 
                           (if (graphic-char-p char) char #\.))))
               (terpri)))
      (do ((pos 0 (+ pos 16)))
          ((>= pos len))
        (let ((count (min 16 (- len pos))))
          (dotimes (i count)
            (setf (svref lbuff i) (elt data (+ pos i))))
          (format t "; ~8,'0X:  " pos)
          (pline lbuff count))))))


(defun usb8 (&rest sequences)
  "Make an (unsigned byte 8) vector from the sequences"
  (apply #'concatenate '(vector (unsigned-byte 8)) sequences))

(defun usb8* (&rest numbers)
  "Make an (unsigned-byte 8) vector from the numbers"
  (make-array (length numbers)
              :element-type '(unsigned-byte 8)
              :initial-contents numbers))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Flags 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmacro defflags (name flags &optional documentation)
  "Macro to define a set of flags"
  `(defparameter ,name
     (list ,@(mapcar (lambda (flag)
                       (destructuring-bind (n v &optional doc) flag
                         (let ((gv (gensym)))
                           `(let ((,gv ,v))
                              (list ',n (ash 1 ,gv) ,gv ,doc)))))
                     flags))
     ,documentation))

(defun pack-flags (flag-names flags)
  "Combine flags"
  (let ((f 0))
    (dolist (flag-name flag-names)
      (let ((n (cadr (assoc flag-name flags))))
        (unless n (error "Flag ~S not found" flag-name))
        (setf f (logior f n))))
    f))

(defun unpack-flags (number flags)
  "Split the number into its flags."
  (let ((f nil)
        (num number))
    (dolist (flag flags)
      (let ((n (cadr flag)))
        (unless (zerop (logand number n))
          (push (car flag) f)
          (setf num (logand num (lognot n))))))
    (unless (zerop num)
      (warn "Input flags ~S remainder ~S" number num))
;;    (assert (zerop number))
    f))

(defun flag-p (number flag-name flags)
  (let ((flag (assoc flag-name flags)))
    (unless flag (error "No flag ~S" flag-name))
    (not (zerop (logand number (cadr flag))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Enums 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
         
(defmacro defenum (name enums)
  `(defparameter ,name
     (list ,@(let ((i 0)) 
                  (mapcar (lambda (enum)
                            (cond 
                              ((symbolp enum)
                               (prog1 `(list ',enum ,i)
                                 (incf i)))
                              (t 
                               (destructuring-bind (n v) enum
                                 (prog1 `(list ',n ,v)
                                   (setf i (1+ v)))))))
                          enums)))))

(defun enum-p (number enum enums)
  (let ((e (assoc enum enums)))
    (unless e (error "No such enum ~S" enum))
    (= number (cadr e))))

(defun enum (enum enums)
  (let ((e (assoc enum enums)))
    (unless e (error "No such enum ~S" enum))
    (cadr e)))

(defun enum-id (number enums)
  (car (find number enums :key #'cadr)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Negotiate flags
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; see http://msdn.microsoft.com/en-us/library/cc236650.aspx
(defflags *negotiate-flags*
  ((:negotiate-56 31 "requests 56-bit encryption")
   (:negotiate-key-exch 30 "requests explicit key exchange. this SHOULD be used")
   (:negotiate-128 29 "requests 128-bit session key")
   (:negotiate-version 25 "requests protocol version number")
   (:negotiate-target-info 23 "indicates targetinfo fields of the challenge message exist")
   (:request-non-nt-session-key 22 "requests usage of LMOWF key generation function")
   (:negotiate-identify 20 "requests and identify level token")
   (:negotiate-extended-sessionsecurity 19 "requests ntlm v2 session security")
   (:target-type-server 17 "targetname must be the server name")
   (:target-type-domain 16 "targetname must be the domain name")
   (:negotiate-always-sign 15 "requests presence of signature block on all messages")
   (:negotiate-oem-workstation-supplied 13 "workstation field is present")
   (:negotiate-oem-domain-supplied 12 "domain name field is present")
   (:annonyomous 11 "if set, the connection should be anonymous")
   (:negotiate-ntlm 9 "requests ntlm v1 security")
   (:negotiate-lm-key 7 "requests lm session key")
   (:negotiate-datagram 6 "requests connectionless authentication")
   (:negotiate-seal 5 "requests session key negotiation")
   (:negotiate-sign 4 "requests session key negotiation for signatures")
   (:request-target 2 "a target name must be supplied in the challenge message")
   (:negotiate-oem 1 "requests oem character encoding")
   (:negotiate-unicode 0 "requests unicode encoding"))
  "Negotiate flags")

(defun pack-negotiate-flags (flags)
  "Pack the list of keyword negotiate flags"
  (pack-flags flags *negotiate-flags*))

(defun unpack-negotiate-flags (num)
  "unpack the negotiate flags"
  (unpack-flags num *negotiate-flags*))

(defun negotiate-flag-p (number flag)
  (flag-p number flag *negotiate-flags*))

;; this must be at the start of every message
(defconstant +ntlm-revision-w2k3+ 15)
(defconstant* +ntlm-signature+ "NTLMSSP")

;; ---------------- packet type definitions follow -----------------

;;
;; NOTE: many of these structures take variable-size arrays. Because the PACKET library demands
;; to know the sizes of these arrays at compile-time, we set them to be 0-length arrays (which 
;; consume no space as far as PACKET is concerned) and extract the properties afterwards.
;;


(defpacket ntlm-field 
  ((len :uint16 :initform 0 :initarg :len :accessor ntlm-field-len)
   (max :uint16 :initform 0 :initarg :len :accessor ntlm-field-max) ;; note that we always initialise to same value as len
   (offset :uint32 :initform 0 :initarg :offset :accessor ntlm-field-offset))
  (:packing 1)
  (:documentation "Used to indicate size and offset of dynamic data stored in message payload."))

(defun make-ntlm-field (len offset)
  (make-instance 'ntlm-field
                 :len len
                 :offset offset))

(defmethod print-object ((field ntlm-field) stream)
  (print-unreadable-object (field stream :type t)
    (format stream ":LEN ~S :OFFSET ~S" (ntlm-field-len field) (ntlm-field-offset field))))

(defpacket ntlm-version
  ((major :uint8 :initform 0 :initarg :major)
   (minor :uint8 :initform 0 :initarg :minor)
   (build :uint16 :initform 0 :initarg :build)
   (reserved (:uint8 3) :initform nil)
   (ntlm-revision :uint8 :initform +ntlm-revision-w2k3+)) ;; always set to 15
  (:packing 1)
  (:documentation "The VERSION structure contains Windows version information that SHOULD be ignored. This structure is used for debugging purposes only and its value does not affect NTLM message processing. It is present in the NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, and AUTHENTICATE_MESSAGE messages only if NTLMSSP_NEGOTIATE_VERSION is negotiated."))

(defun ntlm-version-list (v)
  "Convert an ntlm-version structure into an alist"
  (list (cons :major (slot-value v 'major))
	(cons :minor (slot-value v 'minor))
	(cons :build (slot-value v 'build))))

(defmethod print-object ((version ntlm-version) stream)
  (print-unreadable-object (version stream :type t)
    (format stream ":MAJOR ~S :MINOR ~S :BUILD ~S" 
	    (slot-value version 'major)
	    (slot-value version 'minor)
	    (slot-value version 'build))))

(defun make-ntlm-version (major minor build)
  "Make an ntlm-version structure. MAJOR, MINOR and BUILD are all integers"
  (make-instance 'ntlm-version
		 :major major
		 :minor minor
		 :build build))

(defpacket ntlm-message-signature 
  ((version :uint32 :initform 1)
   (random-pad (:uint8 4) :initform nil :initarg :random-pad)
   (checksum (:uint8 4) :initform nil :initarg :checksum)
   (seqnum :uint32 :initform 0 :initarg :seqnum))
  (:packing 1)
  (:documentation "This version of the NTLMSSP_MESSAGE_SIGNATURE structure MUST be used when the NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag is not negotiated."))

(defun pack-message-signature (crc32 seqnum)
  "Make a message-signature structure for NTLMv1."
  (let (ck rpad)
    (if (= (length crc32) 8)
        (setf rpad (subseq crc32 0 4)
              ck (subseq crc32 4 8))
        (setf rpad (usb8* 0 0 0 0)
              ck (subseq crc32 0 4)))
    (let ((mac (make-instance 'ntlm-message-signature 
                              :seqnum seqnum
                              :random-pad rpad
                              :checksum ck)))
      (pack mac 'ntlm-message-signature))))

(defun unpack-message-signature (buffer)
  (unpack buffer 'ntlm-message-signature))

(defpacket ntlm-message-signature-ex
  ((version :uint32 :initform 1)
   (checksum (:uint8 8) :initform nil :initarg :checksum)
   (seqnum :uint32 :initform 0 :initarg :seqnum))
  (:packing 1)
  (:documentation "This version of the NTLMSSP_MESSAGE_SIGNATURE structure MUST be used when the NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag is negotiated."))

(defun pack-message-signature-ex (crc32 seqnum)
  "Make a message-signature structure for NTLMv2"
  (let ((mac (make-instance 'ntlm-message-signature-ex
			    :seqnum seqnum
			    :checksum (subseq crc32 0 8))))
    (pack mac 'ntlm-message-signature-ex)))

(defun unpack-message-signature-ex (buffer)
  (unpack buffer 'ntlm-message-signature-ex))


(defpacket single-host 
  ((size :uint32 :initform 0 :initarg :size :accessor single-host-size)
   (z4 (:uint8 4) :initform nil)
   (data-present :uint32 :initform 0 :initarg :data-present :accessor single-host-data-present)
   (custom-data (:uint8 4) :initform nil :initarg :custom-data :accessor single-host-custom-data)
   (machine-id (:uint8 32) :initform nil :initarg :machine-id :accessor single-host-machine-id))
  (:packing 1)
  (:documentation "The Single_Host_Data structure allows a client to send machine-specific information within an authentication exchange to services on the same machine. The client can produce additional information to be processed in an implementation-specific way when the client and server are on the same host. If the server and client platforms are different or if they are on different hosts, then the information MUST be ignored. Any fields after the MachineID field MUST be ignored on receipt."))

(defun make-single-host (&key custom-data machine-id)
  "Make a single-host structure for use in make-target-info"
  (make-instance 'single-host 
                 :data-present (if custom-data 1 0)
                 :custom-data custom-data
                 :machine-id machine-id))
             
(defun single-host-list (single-host)
  "Convert a single-host into an alist"
  (list (cons :custom-data (when (single-host-data-present single-host)
                             (single-host-custom-data single-host)))
        (cons :machine-id (single-host-machine-id single-host))))
  
            
;; FILETIME: The date and time as a 64-bit value in little-endian order representing the number of 100-nanosecond intervals elapsed since January 1, 1601 (UTC).
;; 100 nanoseconds since jan 1st 1600
(defparameter *secs-1601-1970* 11643609600)
(defun filetime-unix (filetime)
  "Convert FILETIME into UNIX time"
  (- (truncate filetime 10000000)
     *secs-1601-1970*))
   
(defparameter *secs-1900-1970* 2208988800)
(defun unix ()
  "Number of seconds since Jan 1st 1970"
  (- (get-universal-time)
     *secs-1900-1970*))

(defparameter *secs-1601-1900* 9434620800)
(defun filetime ()
  "Number of 100-nanosecond ticks since Jan 1st 1601"
  (* (+ (get-universal-time)
        *secs-1601-1900*)
     10000000))



;; av-pairs are used to make the target-info array
(defenum *av-pair-ids*
    (:eol
     :nb-computer-name
     :nb-domain-name
     :dns-computer-name
     :dns-domain-name
     :dns-tree-name 
     :flags 
     :timestamp 
     :single-host 
     :target-name 
     :channel-bindings))

(defpacket av-pair 
  ((id :uint16 :initform 0 :initarg :id :accessor av-pair-id)
   (len :uint16 :initform 0 :initarg :len :accessor av-pair-len)
   (value (:uint8 0) :initform nil :initarg :value :accessor av-pair-value))
  (:packing 1)
  (:documentation "The AV_PAIR structure defines an attribute/value pair. Sequences of AV_PAIR structures are used in the CHALLENGE_MESSAGE (section 2.2.1.2) and AUTHENTICATE_MESSAGE (section 2.2.1.3) messages."))

(defmethod print-object ((av-pair av-pair) stream)
  (print-unreadable-object (av-pair stream :type t)
    (format stream ":ID ~S :VALUE ~S" (av-pair-id av-pair) (av-pair-value av-pair))))

(defun make-av-pair (id value)
  "Construct an AV_PAIR object for use in target-info"
  (let ((buff
         (ecase id
           (:eol nil)
           ((:nb-computer-name :nb-domain-name :dns-computer-name
            :dns-domain-name :dns-tree-name :target-name)
            (pack value :wstring))
           (:flags (pack value :uint32))
           (:timestamp (pack value :uint64))
           (:single-host (pack value 'single-host))
           (:channel-bindings value)))) ;;(pack value 'channel-bindings)))))
    (make-instance 'av-pair 
                   :id (enum id *av-pair-ids*)
                   :len (length buff)
                   :value buff)))

(defun pack-av-pair (av-pair)
  (usb8 (pack av-pair 'av-pair)
        (av-pair-value av-pair)))

(defun unpack-av-pair (buffer)
  (multiple-value-bind (av-pair payload) (unpack buffer 'av-pair)
    (let ((id (enum-id (av-pair-id av-pair) *av-pair-ids*))
	  (value (subseq* payload 0 (av-pair-len av-pair))))
      (unless id (error "Invalid AV_PAIR id ~S" (av-pair-id av-pair)))
      (setf (av-pair-id av-pair) 
            id
            (av-pair-value av-pair)
            (ecase id              
              (:eol nil)
              ((:nb-computer-name :nb-domain-name :dns-computer-name
                                  :dns-domain-name :dns-tree-name :target-name)
               (unpack value :wstring))
              (:flags (unpack value :uint32))
              (:timestamp (unpack value :uint64))
              (:single-host (single-host-list (unpack value 'single-host)))
              (:channel-bindings value)))) ;;(unpack value 'channel-bindings))))
      av-pair))

(defun make-target-info (&key nb-computer-name nb-domain-name dns-computer-name 
                           dns-domain-name dns-tree-name flags 
                           timestamp single-host target-name channel-bindings ordering)
  "Make a list of AV_PAIR objects used for the target-info parameter to pack-challenge-message.
Specify the ordering of the AV_PAIR objects if required."
  (let ((av-pairs nil)
        (order 
         (if ordering 
             ordering
             '(:nb-computer-name :nb-domain-name :dns-computer-name :dns-domain-name :dns-tree-name :flags :timestamp
               :single-host :target-name :channel-bindings))))
    (labels ((add-av-pair (id value)
               (when (or value (eq id :eol))
                 (push (make-av-pair id value) av-pairs))))
      (dolist (name order)
        (ecase name
          (:nb-computer-name 
           (add-av-pair :nb-computer-name nb-computer-name))
          (:nb-domain-name
           (add-av-pair :nb-domain-name nb-domain-name))
          (:dns-computer-name 
           (add-av-pair :dns-computer-name dns-computer-name))
          (:dns-domain-name 
           (add-av-pair :dns-domain-name dns-domain-name))
          (:dns-tree-name
           (add-av-pair :dns-tree-name dns-tree-name))
          (:flags
           (add-av-pair :flags flags))
          (:timestamp 
           (add-av-pair :timestamp timestamp))
          (:single-host
           (add-av-pair :single-host single-host))
          (:target-name
           (add-av-pair :target-name target-name))
          (:channel-bindings
           (add-av-pair :channel-bindings channel-bindings))))
      (add-av-pair :eol nil))

    (nreverse av-pairs)))

(defun unpack-target-info (buffer)
  (let (av-pairs)
    (do ((len (length buffer))
         (offset 0)
         (eol nil))
        ((or eol (>= offset len)))
      (let ((av-pair (unpack-av-pair (subseq buffer offset))))
        (incf offset (+ 4 (av-pair-len av-pair)))
        (when (eq (av-pair-id av-pair) :eol)
          (setf eol t))
        (push av-pair av-pairs)))
    (nreverse av-pairs)))

(defun target-info-list (target-info)
  "Convert target-info into an assoc list"
  (let (res)
    (dolist (info target-info)
      (unless (eq (av-pair-id info) :eol)
        (push (cons (av-pair-id info) (av-pair-value info))
              res)))
    (nreverse res)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; negotiate message
;; this is sent form the client to the server 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defpacket negotiate-message
  ((signature (:string 8) :initform +ntlm-signature+)
   (message-type :uint32 :initform 1)
   (negotiate-flags :uint32 :initform 0 :initarg :flags :accessor negotiate-message-flags)
   (domain-field ntlm-field :initarg :domain-field :accessor negotiate-message-domain-field
                 :initform (make-instance 'ntlm-field))
   (workstation-field ntlm-field :initarg :workstation-field :accessor negotiate-message-workstation-field
                      :initform (make-instance 'ntlm-field))
   ;; payload
   (version (ntlm-version 0) :initarg :version :initform nil)
   (domain (:string 0) :initform nil :accessor negotiate-message-domain)
   (workstation (:string 0) :initform nil :accessor negotiate-message-workstation))
  (:packing 1)
  (:documentation "The NEGOTIATE_MESSAGE defines an NTLM Negotiate message that is sent from the client to the server. This message allows the client to specify its supported NTLM options to the server."))

(defmethod print-object ((msg negotiate-message) stream)
  (print-unreadable-object (msg stream :type t)
    (format stream ":DOMAIN ~S :WORKSTATION ~S" (negotiate-message-domain msg) 
            (negotiate-message-workstation msg))))

(defun pack-negotiate-message (flags &key domain workstation version)
  "Generate a NEGOTIATE message"
  (let ((msg (make-instance 'negotiate-message 
                            :flags (pack-negotiate-flags flags)))
        (dbuff nil)
        (wbuff nil)
	(vbuff nil)
        (offset (type-size 'negotiate-message)))

    ;; version
    (when version
      (setf vbuff (pack version 'ntlm-version)
	    offset (+ offset (type-size 'ntlm-version))))

    ;; when supplied a domain
    (when domain
      (setf dbuff 
	    (pack domain :string)
	    (negotiate-message-domain-field msg)
	    (make-ntlm-field (length dbuff) offset)
	    offset 
	    (+ offset (length dbuff))))

    ;; when supplied a workstation
    (when workstation
      (setf wbuff 
	    (pack workstation :string)
	    (negotiate-message-workstation-field msg)
	    (make-ntlm-field (length wbuff) offset)
	    offset 
	    (+ offset (length wbuff))))

    ;; concat all the buffers
    (usb8 (pack msg 'negotiate-message)
          vbuff
          dbuff
          wbuff)))

(defun negotiate-message-list (msg)
  "Convert the negotiate-message structure into an assoc list"
  (list (cons :flags (negotiate-message-flags msg))
	(cons :version (slot-value msg 'version))
	(cons :domain (negotiate-message-domain msg))
	(cons :workstation (negotiate-message-workstation msg))))

(defun unpack-negotiate-message (buffer)
  "Extract the negotiate message from the buffer"
  (multiple-value-bind (msg payload) (unpack buffer 'negotiate-message)
    (let ((flags (unpack-negotiate-flags (negotiate-message-flags msg)))
          (tsize (type-size 'negotiate-message)))
      (setf (negotiate-message-flags msg) flags)
      
      ;; version
      (if (member :NEGOTIATE-VERSION (negotiate-message-flags msg))
	  (setf (slot-value msg 'version)
		(ntlm-version-list (unpack (subseq payload 0 (type-size 'ntlm-version))
					   'ntlm-version)))
	  (setf (slot-value msg 'version) nil))

      ;; domain
      (let ((dfield (negotiate-message-domain-field msg)))
	(if (zerop (ntlm-field-len dfield))
	    (setf (negotiate-message-domain msg) nil)
	    (setf (negotiate-message-domain msg)
		  (unpack (subseq* payload 
				   (- (ntlm-field-offset dfield) tsize)
				   (ntlm-field-len dfield)) 
			  :string))))

      ;; workstation
      (let ((wfield (negotiate-message-workstation-field msg)))
	(if (zerop (ntlm-field-len wfield))
	    (setf (negotiate-message-workstation msg) nil)
	    (setf (negotiate-message-workstation msg)
		  (unpack (subseq* payload 
				   (- (ntlm-field-offset wfield) tsize)
				   (ntlm-field-len wfield))
			  :string))))

      (negotiate-message-list msg))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; challege message 
;; this is sent from the server back to the client
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defpacket challenge-message
  ((signature (:string 8) :initform +ntlm-signature+)
   (message-type :uint32 :initform 2)
   (target-name-field ntlm-field :initarg :target-name-field 
                      :initform (make-ntlm-field 0 0)
                      :accessor challenge-message-target-name-field)
   (negotiate-flags :uint32 :initform 0 :initarg :flags :accessor challenge-message-flags)
   (server-challenge (:uint8 8) :initform nil :initarg :challenge)
;; this is supposed to be reserved (i.e. all 0) but the Windows HTTP Server sneakily sends something here.
;; what is it for?
   (reserved (:uint8 8) :initform #(#x60 #xD6 #xAF #x01 00 00 00 00)) 
   (target-info-field ntlm-field :initform (make-ntlm-field 0 0)
                      :initarg :target-info-field :accessor challenge-message-target-info-field)
   ;; payload 
   (version (ntlm-version 0) :initform nil :initarg :version)
   (target-name (:wstring 0) :initform nil :accessor challenge-message-target-name)
   (target-info (av-pair 0) :initform nil :accessor challenge-message-target-info))
  (:packing 1)
  (:documentation "The CHALLENGE_MESSAGE defines an NTLM challenge message that is sent from the server to the client. The CHALLENGE_MESSAGE is used by the server to challenge the client to prove its identity. For connection-oriented requests, the CHALLENGE_MESSAGE generated by the server is in response to the NEGOTIATE_MESSAGE (section 2.2.1.1) from the client."))

(defmethod print-object ((msg challenge-message) stream)
  (print-unreadable-object (msg stream :type t)
    (format stream ":TARGET-NAME ~S" (challenge-message-target-name msg))))

(defun pack-challenge-message (flags server-challenge &key target-name target-info version)
  "Generate a CHALLENGE message for the server to send back to the client. 

SERVER-CHALLENGE should be an array of 8 random bytes. This can be generated by calling server-challenge.
VERSION should be the result of calling make-ntlm-version.

TARGET-NAME should be a string.

TARGET-INFO should be the result of calling make-target-info."
  (let ((msg (make-instance 'challenge-message 
                            :flags (pack-negotiate-flags flags)
                            :challenge server-challenge))
        (offset (type-size 'challenge-message))
        (tbuff nil)
        (ibuff nil)
	(vbuff nil))

    ;; version
    (when version
      (setf vbuff (pack version 'ntlm-version)
	    offset (+ offset (type-size 'ntlm-version))))

    ;; target-name 
    (when target-name
      (setf tbuff 
	    (pack target-name :wstring)
	    (challenge-message-target-name-field msg)
	    (make-ntlm-field (length tbuff) offset)
	    offset
	    (+ offset (length tbuff))))

    ;; target-info
    (when target-info
      (setf ibuff 
	    (apply #'usb8 (mapcar #'pack-av-pair target-info))
	    (challenge-message-target-info-field msg)
	    (make-ntlm-field (length ibuff) offset)
	    offset
	    (+ offset (length ibuff))))
      
    (usb8 (pack msg 'challenge-message)
		  vbuff
          tbuff
          ibuff)))

(defun challenge-message-list (msg target-info-buffer)
  (list (cons :flags (challenge-message-flags msg))
	(cons :version (slot-value msg 'version))
	(cons :target-name (challenge-message-target-name msg))
	(cons :target-info 
          (target-info-list (challenge-message-target-info msg)))
	(cons :server-challenge (slot-value msg 'server-challenge))
    (cons :target-info-buffer target-info-buffer)))

(defun unpack-challenge-message (buffer)
  (multiple-value-bind (msg payload) (unpack buffer 'challenge-message)
    (let ((tfield (challenge-message-target-name-field msg))
          (ifield (challenge-message-target-info-field msg))
          (flags (unpack-negotiate-flags (challenge-message-flags msg)))
          (tsize (type-size 'challenge-message))
          (target-info-buffer nil))

      (setf (challenge-message-flags msg) flags)

      ;; version
      (if (member :NEGOTIATE-VERSION (challenge-message-flags msg))
          (setf (slot-value msg 'version)
                (ntlm-version-list (unpack (subseq payload 0 (type-size 'ntlm-version))
                                           'ntlm-version)))
          (setf (slot-value msg 'version)
                nil))

      ;; target-name 
      (if (zerop (ntlm-field-len tfield))
          (setf (challenge-message-target-name msg) nil)
          (setf (challenge-message-target-name msg)
                (unpack (subseq* payload 
                                 (- (ntlm-field-offset tfield) tsize)
                                 (ntlm-field-len tfield))
                        :wstring)))

      ;; target-info av-pairs 
      (setf (challenge-message-target-info msg) nil)
      ;; only get the av-pairs when the field says there is some to get 
      (when (> (ntlm-field-len ifield) 0)
        ;; extract the binary data for later use 
        (setf target-info-buffer 
              (subseq* payload 
                       (- (ntlm-field-offset ifield) tsize)
                       (ntlm-field-len ifield)))

        (do ((len (length payload))
             (offset (- (ntlm-field-offset ifield) tsize))
             (eol nil))
            ((or eol (>= offset len)))
          (let ((av-pair (unpack-av-pair (subseq payload offset))))
            (incf offset (+ 4 (av-pair-len av-pair)))
            (when (eq (av-pair-id av-pair) :eol)
              (setf eol t))
            (push av-pair (challenge-message-target-info msg))))
        
        (setf (challenge-message-target-info msg)
              (reverse (challenge-message-target-info msg))))

      (challenge-message-list msg target-info-buffer))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; this is sent back to the server by the cliehnt 
;; as the final authentiaciont message
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defpacket authenticate-message
  ((signature (:string 8) :initform +ntlm-signature+)
   (message-type :uint32 :initform 3)
   (lm-field ntlm-field :initform nil :initarg :lm-field 
             :accessor authenticate-message-lm-field)
   (nt-field ntlm-field :initform nil :initarg :nt-field 
             :accessor authenticate-message-nt-field)
   (domain-field ntlm-field :initform nil :initarg :domain-field 
                 :accessor authenticate-message-domain-field)
   (username-field ntlm-field :initform nil :initarg :username-field 
                   :accessor authenticate-message-username-field)
   (workstation-field ntlm-field :initform nil :initarg :workstation-field 
                      :accessor authenticate-message-workstation-field)
   (session-key-field ntlm-field :initform nil :initarg :key-field
                       :accessor authenticate-message-session-key-field)
   (negotiate-flags :uint32 :initform 0 :initarg :flags :accessor authenticate-message-flags)
   ;; payload
   (version (ntlm-version 0) :initform nil)
   (mic (:uint8 0) :initform nil)
   (lm-response (:uint8 0) :initform nil :initarg :lm-response
                :accessor authenticate-message-lm-response)
   (nt-response (:uint8 0) :initform nil :initarg :nt-response
                :accessor authenticate-message-nt-response)
   (domain (:wstring 0) :initform "" :initarg :domain
           :accessor authenticate-message-domain)
   (username (:wstring 0) :initform "" :initarg :username
             :accessor authenticate-message-username)
   (workstation (:wstring 0) :initform "" :initarg :workstation
                :accessor authenticate-message-workstation)
   (encrypted-session-key (:uint8 0) :initform nil :initarg :session-key
             :accessor authenticate-message-encrypted-session-key))
  (:packing 1))


(defmethod print-object ((msg authenticate-message) stream)
  (print-unreadable-object (msg stream :type t :identity t)))

(defun pack-authenticate-message (flags &key lm-response nt-response 
					  domain username workstation 
					  encrypted-session-key version mic)
  "Generate an AUTHENTICATE message for the client to send back to the server.

LM-RESPONSE and NT-RESPONSE should be the results of calling the lm-response(-v1,-v1*,-v2)/nt-response(-v1,-v2) functions.

DOMAIN, USERNAME, WORKSTATION should be strings.

ENCRYPTED-SESSION-KEY should be the result of calling encrypted-session-key.

VERSION should be the result of calling make-ntlm-version.

MIC is optional and can be ignored. It should be the result of calling mic."
  (let ((msg (make-instance 'authenticate-message
                            :flags (pack-negotiate-flags flags)))
        (offset (type-size 'authenticate-message))
        (footer nil))

    (when version
      (let ((buff (pack version 'ntlm-version)))
	(setf offset 
	      (+ offset (length buff))
	      footer
	      (usb8 footer buff))))

    (when mic
      (setf offset
	    (+ offset (length mic))
	    footer
	    (usb8 footer mic)))

    ;; lm-response
    (when lm-response
      (setf (authenticate-message-lm-field msg)
            (make-ntlm-field (length lm-response) offset)
            offset
            (+ offset (length lm-response))
            footer
            (usb8 footer lm-response)))
    
    ;; nt-response
    (when nt-response
      (setf (authenticate-message-nt-field msg)
            (make-ntlm-field (length nt-response) offset)
            offset
            (+ offset (length nt-response))
            footer
            (usb8 footer nt-response)))

    ;; domain
    (when domain
      (let ((buff (pack domain :wstring)))
        (setf (authenticate-message-domain-field msg)
              (make-ntlm-field (length buff) offset)
              offset
              (+ offset (length buff))
              footer 
              (usb8 footer buff))))

    ;; username 
    (when username
      (let ((buff (pack username :wstring)))
        (setf (authenticate-message-username-field msg)
              (make-ntlm-field (length buff) offset)
              offset
              (+ offset (length buff))
              footer 
              (usb8 footer buff))))

    ;; workstation
    (when workstation
      (let ((buff (pack workstation :wstring)))
        (setf (authenticate-message-workstation-field msg)
              (make-ntlm-field (length buff) offset)
              offset
              (+ offset (length buff))
              footer 
              (usb8 footer buff))))

    ;; encrypted session-key
    (when encrypted-session-key
      (setf (authenticate-message-session-key-field msg)
              (make-ntlm-field (length encrypted-session-key) offset)
              offset
              (+ offset (length encrypted-session-key))
              footer 
              (usb8 footer encrypted-session-key)))

    ;; done
    (usb8 (pack msg 'authenticate-message)
          footer)))

(defun authenticate-message-list (msg)
  (list (cons :flags (authenticate-message-flags msg))
	(cons :version (slot-value msg 'version))
	(cons :mic (slot-value msg 'mic))
	(cons :lm-response (authenticate-message-lm-response msg))
	(cons :nt-response (authenticate-message-nt-response msg))
	(cons :domain (authenticate-message-domain msg))
	(cons :username (authenticate-message-username msg))
	(cons :workstation (authenticate-message-workstation msg))
	(cons :encrypted-session-key (authenticate-message-encrypted-session-key msg))))


(defun unpack-authenticate-message (buffer)
  (multiple-value-bind (msg payload) (unpack buffer 'authenticate-message)

    (setf (authenticate-message-flags msg)
	  (unpack-negotiate-flags (authenticate-message-flags msg)))

    (let ((base (type-size 'authenticate-message)))

      ;; version
      (if (member :NEGOTIATE-VERSION (authenticate-message-flags msg))
	  (setf (slot-value msg 'version)
		(let ((v (unpack (subseq payload 0 (type-size 'ntlm-version))
				 'ntlm-version)))
		  (ntlm-version-list v)))
	  (setf (slot-value msg 'version)
		nil))
      
      ;; mic
      ;; FIXME: extract the MIC somehow? It's not easy to do because in some versions of Windows 
      ;; it isn't present and there is no information in the flags to say whether its there.
      ;; for the moment we must ignore it I think
      ;; The MIC field is omitted in Windows NT, Windows 2000, Windows XP, and Windows Server 2003.
      (setf (slot-value msg 'mic) nil)
      
      ;; extract the payload fields
      (labels ((get-field (field)
		 (let ((len (ntlm-field-len field)))
		   (unless (zerop len)
		     (subseq* payload 
			      (- (ntlm-field-offset field) base)
			      len)))))
	;; lm-response
	(let ((field (authenticate-message-lm-field msg)))
	  (setf (authenticate-message-lm-response msg)
		(get-field field)))
	
	;; nt-response
	(let ((field (authenticate-message-nt-field msg)))
	  (setf (authenticate-message-nt-response msg)
		(get-field field)))
	
	;; domain
	(let ((field (authenticate-message-domain-field msg)))
	  (let ((d (get-field field)))
	    (when d 
	      (setf (authenticate-message-domain msg)
		    (unpack d :wstring)))))
	
	;; username
	(let ((field (authenticate-message-username-field msg)))
	  (let ((d (get-field field)))
	    (when d 
	      (setf (authenticate-message-username msg)
		    (unpack d :wstring)))))
	
	;; workstation
	(let ((field (authenticate-message-workstation-field msg)))
	  (let ((d (get-field field)))
	    (when d 
	      (setf (authenticate-message-workstation msg)
		    (unpack d :wstring)))))
	
	;; encrypted session-key
	(let ((field (authenticate-message-session-key-field msg)))
	  (setf (authenticate-message-encrypted-session-key msg)
		(get-field field)))))

    (authenticate-message-list msg)))



