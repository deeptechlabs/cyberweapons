;; mailcrypt.el v1.5, mail encryption with RIPEM and PGP
;; Copyright (C) 1993  Jin Choi <jsc@mit.edu>
;; Any comments or suggestions welcome.
;; Inspired by pgp.el, by Gray Watson <gray@antaire.com>.

;; LCD Archive Entry:
;; mailcrypt|Jin S Choi|jsc@mit.edu|
;; Encryption/decryption for mail using RIPEM or PGP. Supports RMAIL and VM.|
;; 2-Apr-1994|1.5|~/interfaces/mailcrypt.el.Z|

;;{{{ Licensing
;; This file is intended to be used with GNU Emacs.

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 2, or (at your option)
;; any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with GNU Emacs; see the file COPYING.  If not, write to
;; the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
;;}}}

;;{{{ Change Log
;;{{{ Changes from 1.4:
;; * Call mail-extract-address-components on the recipients if we guessed
;;   them from the header fields.
;; * If you don't replace a message with its decrypted version, it will now
;;   pop you into a view buffer with the contents of the message.
;; * Added support for mh-e, contributed by Fritz Knabe <Fritz.Knabe@ecrc.de>
;; * Fixed bug in snarfing keys from menubar under GNUS.
;; * Fixed RIPEM verification problem, thanks to Sergey Gleizer
;;   <sgleizer@cs.nmsu.edu>.
;;}}}
;;{{{ Changes from 1.3:
;; * Temp display function does not barf on F-keys or mouse events.
;;     Thanks to Jonathan Stigelman <stig@key.amdahl.com>
;; * Lucid emacs menu support provided by William Perry <wmperry@indiana.edu>
;; * Cited signed messages would interfere with signature 
;;	verification; fixed.
;;}}}
;;{{{ Changes from 1.2:
;; * Added menu bar support for emacs 19.
;; * Added GNUS support thanks to Samuel Druker <samuel@telmar.com>.
;;}}}
;;{{{ Changes from 1.1:
;; * Added recipients field to mc-encrypt-message.
;;}}}
;;{{{ Changes from 1.0:
;; * Fixed batchmode bug in decryption, where unsigned messages would return
;;   with exit code of 1.
;;}}}
;;{{{ Changes from 0.3b:
;; * Only set PGPPASSFD when needed, so PGP won't break when used
;;   in shell mode.
;; * Use call-process-region instead of shell-command-on-region in order
;;   to detect exit codes.
;; * Changed mc-temp-display to not use the kill ring.
;; * Bug fixes.
;;}}}
;;{{{ Changes from 0.2b:
;; * Prompts for replacement in mc-rmail-decrypt-message.
;; * Bug fixes.
;;}}}
;;{{{ Changes from 0.1b:
;; * Several bug fixes.
;; Contributed by Jason Merrill <jason@cygnus.com>:
;; * VM mailreader support
;; * Support for addresses with spaces and <>'s in them
;; * Support for using an explicit path for the pgp executable
;; * Key management functions
;; * The ability to avoid some of the prompts when encrypting
;; * Assumes mc-default-scheme unless prefixed
;;}}}
;;}}}

;;{{{ Usage:
;;{{{ Installation:

;; To use, put something like the following elisp into your .emacs file.
;; You may want to set some of the user variables there as well,
;; particularly mc-default-scheme.

;; Currently supported modes are RMAIL, VM, mh-e, and gnus. Check out
;; the section on mode specific functions to see what you can bind.

;;{{{ A sample hook for a writing mode:
;;(autoload 'mc-encrypt-message "mailcrypt" nil t)
;;(autoload 'mc-sign-message "mailcrypt" nil t)
;;(autoload 'mc-insert-public-key "mailcrypt" nil t)
;;(defun mc-install-write-mode ()
;;  (require 'mailcrypt)
;;  (if (eq window-system 'x)
;;      (mc-create-write-menu-bar))
;;  (local-set-key "\C-ce" 'mc-encrypt-message)
;;  (local-set-key "\C-cs" 'mc-sign-message)
;;  (local-set-key "\C-ca" 'mc-insert-public-key))

;;(add-hook 'mail-mode-hook 'mc-install-write-mode)
;;(add-hook 'news-reply-mode-hook 'mc-install-write-mode)
;;}}}

;;{{{ A sample hook for a reading mode:
;;(autoload 'mc-rmail-decrypt-message "mailcrypt" nil t)
;;(autoload 'mc-rmail-verify-signature "mailcrypt" nil t)
;;(autoload 'mc-snarf-keys "mailcrypt" nil t)
;;(add-hook 'rmail-mode-hook
;;	  '(lambda ()
;;	     (require 'mailcrypt)
;;	     (if (eq window-system 'x)
;;		 (mc-create-read-menu-bar))
;;	     (local-set-key "\C-cd" 'mc-rmail-decrypt-message)
;;	     (local-set-key "\C-cv" 'mc-rmail-verify-signature)
;;	     (local-set-key "\C-cs" 'mc-snarf-keys)))
;;}}}

;; hooks to use:
;; PACKAGE 	READ HOOK		WRITE HOOK
;; -------	---------		----------
;; rmail: 	rmail-mode-hook		mail-mode-hook
;; vm:		vm-mode-hook		mail-mode-hook
;; mh-e:	mh-folder-mode-hook	mh-letter-mode-hook
;; gnus:	gnus-summary-mode-hook	news-reply-mode
;;}}}


;;}}}
;;{{{ Security Considerations

;; I've tried to write this with security in mind, especially in
;; regard to the passphrase used to encrypt the private key.

;; No passphrase is ever passed by command line or environment
;; variable. The passphrase may be temporarily stored into an elisp
;; variable to allow multiple encryptions/decryptions within a short
;; period of time without having to type it in each time. It will
;; deactivate automatically some time after its last use (default one
;; minute; see `mc-passwd-timeout') if you are running emacs 19. This
;; is to prevent someone from walking up to your computer while you're
;; gone and looking up your passphrase. If you are using an older
;; version of emacs, you can either set mc-passwd-timeout to nil,
;; which disables passphrase cacheing, or manually deactivate your
;; passphrase when you are done with it by typing `M-x mc-deactivate-passwd'.

;; The passphrase may still be visible shortly after entry as lossage
;; (the last 100 characters entered can be displayed by typing 
;; `C-h l'). I've taken no steps to deal with this, as I don't think
;; anything *can* be done. If you are the paranoid type, make sure you
;; type at least a hundred keys after entering your passphrase before
;; you leave your emacs unattended.

;; If you are truly security conscious, you should, of course, never
;; leave your computer unattended while you're logged in....

;;}}}
;;{{{ CAVEAT:

;; This code breaks if you have "Verbose=0" in your config.txt for PGP.
;; Thanks to Ciamac Moallemi (ciamac@hplms2.hpl.hp.com) for pointing this out.

;; This was written under emacs v19. Its behavior under older versions
;; of emacs is untested. If something breaks under emacs 18, please
;; feel free to fix it and send me patches.

;;}}}
;;{{{ Note:
;; The funny triple braces you see are used by `folding-mode', a minor
;; mode by Jamie Lokier, available from the elisp archive.
;;}}}

(require 'comint)
(require 'mail-utils)

;;{{{ User variables.

(defvar mc-default-scheme 'pgp "*Default encryption scheme to use.")
(defvar mc-passwd-timeout "1 min" 
  "*Time to deactivate password in after a use, or nil for immediately.")

(defvar mc-pgp-user-id (user-login-name) "*Your PGP user ID.")
(defvar mc-ripem-user-id (or (getenv "RIPEM_USER_NAME")
			     (user-full-name) "*Your RIPEM user ID."))

(defvar mc-pgp-always-sign nil "*Always sign encrypted PGP messages.")
(defvar mc-always-replace nil "*Decrypt messages in place without prompting.")
(defvar mc-use-default-recipients nil
  "*Assume that the message should be encoded for everyone listed in the To:
and Cc: fields.")
(defvar mc-encrypt-for-me nil
  "*Encrypt all outgoing messages with user's public key.")

;;}}}
;;{{{ Program variables and constants.

(defvar mc-timer nil "Timer object for password deactivation.")

(defvar mc-pgp-passwd nil "Your PGP passphrase.")
(defvar mc-ripem-passwd nil "Your RIPEM passphrase.")

(defvar mc-pgp-path "pgp" "*The PGP executable.")
(defvar mc-ripem-path "ripem" "*The RIPEM executable.")

(defvar mc-ripem-pubkeyfile (getenv "RIPEM_PUBLIC_KEY_FILE")
  "*Location of RIPEM public key file.")				

(defconst mc-pgp-msg-begin-line "-----BEGIN PGP MESSAGE-----"
  "Text for start of PGP message delimiter.")
(defconst mc-pgp-msg-end-line "-----END PGP MESSAGE-----"
  "Text for end of PGP message delimiter.")
(defconst mc-pgp-signed-begin-line "-----BEGIN PGP SIGNED MESSAGE-----"
  "Text for start of PGP signed messages.")
(defconst mc-pgp-signed-end-line "-----END PGP SIGNATURE-----"
  "Text for end of PGP signed messages.")
(defconst mc-pgp-key-begin-line "-----BEGIN PGP PUBLIC KEY BLOCK-----"
  "Text for start of PGP public key.")
(defconst mc-pgp-key-end-line "-----END PGP PUBLIC KEY BLOCK-----"
  "Text for end of PGP public key.")
(defconst mc-ripem-key-begin-line "-----BEGIN PUBLIC KEY-----"
  "Text for start of RIPEM public key.")
(defconst mc-ripem-key-end-line "-----END PUBLIC KEY-----"
  "Text for end of RIPEM public key.")
(defconst mc-ripem-msg-begin-line "-----BEGIN PRIVACY-ENHANCED MESSAGE-----"
  "Text for start of RIPEM message delimiter.")
(defconst mc-ripem-msg-end-line "-----END PRIVACY-ENHANCED MESSAGE-----"
  "Text for end of RIPEM message delimiter.")

;;}}}
;;{{{ Utility functions.

(defun mc-split (regexp str)
  "Splits STR into a list of elements which were separated by REGEXP,
stripping initial and trailing whitespace."
  (let ((data (match-data))
	beg end	retval)
    (string-match "[ \t\n]*" str)	; Will always match at 0
    (setq beg (match-end 0))
    ;; This will break if there are newlines in str XXX
    (setq end (string-match "[ \t\n]*$" str))
    (while (string-match regexp str beg)
      (setq retval (append retval 
			   (list (substring str beg (match-beginning 0)))))
      (setq beg (match-end 0)))
    (if (not (= (length str) beg))	; Not end
	(setq retval (append retval (list (substring str beg end)))))
    (store-match-data data)
    retval))

(defun mc-temp-display (beg end &optional name)
  (let (tmp)
    (if (not name)
	(setq name "*Mailcrypt Temp*"))
    (setq tmp (buffer-substring beg end))
    (delete-region beg end)
    (save-excursion
      (set-buffer (generate-new-buffer name))
      (insert tmp)
      (goto-char (point-min))
      (save-window-excursion
	(shrink-window-if-larger-than-buffer 
	 (display-buffer (current-buffer)))
	(message "Press any key to remove the %s window." name)

	(cond ((and (string-match "19\\." emacs-version)
		    (not (string-match "Lucid" (emacs-version))))
	       (read-event))
	      (t
	       (read-char)))
	(kill-buffer (current-buffer))))))

;;}}}
;;{{{ Passphrase management

(defun mc-activate-passwd (scheme)
  (if (fboundp 'run-at-time)
      (progn
	(if mc-timer (cancel-timer mc-timer))
	(setq mc-timer (if mc-passwd-timeout
			   (run-at-time mc-passwd-timeout 
					nil 'mc-deactivate-passwd)
			 nil))))
  (cond ((eq scheme 'pgp)
	 (if (not mc-pgp-passwd)
	     (setq mc-pgp-passwd (comint-read-noecho "PGP Password: "))))
	((eq scheme 'ripem)
	 (if (not mc-ripem-passwd)
	     (setq mc-ripem-passwd (comint-read-noecho "RIPEM Password: "))))
	(t
	 (error "Encryption scheme %s not recognized" scheme))))

(defun mc-deactivate-passwd ()
  "*Deactivates both PGP and RIPEM passwords."
  (interactive)
  (and mc-timer (fboundp 'cancel-timer) (cancel-timer mc-timer))
  (setq mc-pgp-passwd nil
	mc-ripem-passwd nil)
  (message "password deactivated"))

;;}}}
;;{{{ Encryption

(defun mc-cleanup-recipient-headers (str)
  ;; Takes a comma separated string of recipients to encrypt for and,
  ;; assuming they were possibly extracted from the headers of a reply,
  ;; returns a list of the address componnts.
  (mapcar (function
	   (lambda (x)
	     (car (cdr (mail-extract-address-components x)))))
	  (mc-split "\\([ \t\n]*,[ \t\n]*\\)+" str)))

(defun mc-encrypt-message (&optional recipients scheme)
  "*Encrypt the message to RECIPIENTS using the given encryption SCHEME.
RECIPIENTS is a comma separated string. If SCHEME is nil, use the value
of `mc-default-scheme'."
  (interactive
   (if current-prefix-arg
       (list nil (read-from-minibuffer "Encryption Scheme: " nil nil t))))
  
  (let (args start signed-p retval)
    (or scheme (setq scheme mc-default-scheme))
    (setq recipients
	  (cond (recipients		; given as function argument
		 (mc-split "\\([ \t\n]*,[ \t\n]*\\)+" recipients))
		(mc-use-default-recipients
		 (mc-cleanup-recipient-headers
		  (concat (mail-fetch-field "to" nil t) ", "
			  (mail-fetch-field "cc" nil t))))
		(t			; prompt for it
		 (mc-cleanup-recipient-headers
		  (read-from-minibuffer
		   "Recipients: " (concat (mail-fetch-field "to" nil t) ", "
					  (mail-fetch-field "cc" nil t)))))))

    (or recipients
	(error "No recipients!"))

    (cond ((eq scheme 'pgp)
	   (and mc-encrypt-for-me
		(setq recipients (cons mc-pgp-user-id recipients)))
	   (setq args (list "+batchmode" "-feat"))
	   (if (or mc-pgp-always-sign (y-or-n-p "Sign the message? "))
	       (setq signed-p t
		     args (append args (list "-su" mc-pgp-user-id))))
	   (setq args (append args recipients))
	   (goto-char (point-min))
	   (search-forward (concat "\n" mail-header-separator "\n"))
	   (setq start (point))
	   (let ((process-environment process-environment))
	     ;; Don't need to ask for the passphrase if not signing.
	     (if signed-p
		 (progn (mc-activate-passwd 'pgp)
			(insert mc-pgp-passwd "\n")
			(setq process-environment (cons "PGPPASSFD=0"
							process-environment))))
	     (message "Encrypting...")
	     ;; Use call-process-region rather than shell-command-on-region
	     ;; to get the exit code.
	     (setq retval (apply 'call-process-region
				 (append (list start (point-max) mc-pgp-path
					       t t nil)
					 args)))
	     (or mc-passwd-timeout (mc-deactivate-passwd))
	     (if (= retval 0)
		 (progn
		   (goto-char start)
		   (search-forward mc-pgp-msg-begin-line)
		   (search-backward mc-pgp-msg-begin-line)
		   (mc-temp-display start (point) "*Encryption*"))
	       (error "Error while encrypting. Hit C-x u to undo."))))
	  ((eq scheme 'ripem)
	   (and mc-encrypt-for-me
		(setq recipients (cons mc-ripem-user-id recipients)))
	   ;; Anyone know any better way to do the following?
	   (setq args (append (list "-e" "-m" "encrypted"
				    "-T" "a" "-k" "-")
			      (apply 'append
				     (mapcar (lambda (x) (list "-r" x)) 
					     recipients))))
	   (goto-char (point-min))
	   (search-forward (concat "\n" mail-header-separator "\n"))
	   (setq start (point))
	   (mc-activate-passwd 'ripem)
	   (insert mc-ripem-passwd "\n")
	   (message "Encrypting...")
	   (setq retval (apply 'call-process-region
			       (append (list start (point-max) mc-ripem-path
					     t t nil)
				       args)))
	   (or mc-passwd-timeout (mc-deactivate-passwd))
	   (if (/= retval 0)
	       (error "Error while encrypting. Hit C-x u to undo.")))
	  (t
	   (error "Encryption scheme %s not recognized" scheme)))))

;;}}}
;;{{{ Decryption

(defun mc-decrypt-message ()
  "*Decrypt whatever message is in the current buffer. Return t on success."
  (interactive)
  (let (start msg retval)
    (goto-char (point-min))
    (cond ((re-search-forward (concat "^" mc-pgp-msg-begin-line) nil t)
	   (re-search-backward (concat "^" mc-pgp-msg-begin-line))
	   (setq start (point))
	   (mc-activate-passwd 'pgp)
	   (or buffer-read-only
	       (insert mc-pgp-passwd "\n"))
	   (re-search-forward (concat "^" mc-pgp-msg-end-line))
	   (cond (buffer-read-only
		  (setq msg (buffer-substring start (point)))
		  (pop-to-buffer (get-buffer-create "*Decrypted Message*"))
		  (erase-buffer)
		  (insert mc-pgp-passwd "\n" msg)
		  (setq start (point-min))))
	   (let ((process-environment 
		  (cons "PGPPASSFD=0" process-environment)))
	     (message "Decrypting...")
	     (setq retval (call-process-region start (point) mc-pgp-path t t
					       nil "-f"))
	     (or mc-passwd-timeout (mc-deactivate-passwd))
	     (if (= retval 0)
		 (prog1
		     t
		   (goto-char start)
		   (or (re-search-forward "^Signature made.*\n" nil t)
		       (search-forward "Just a moment......"))
		   (mc-temp-display start (point) "*Decryption*"))
	       (mc-temp-display start (point) "*ERROR*")
	       nil)))
	  ((search-forward mc-ripem-msg-begin-line nil t)
	   (search-backward mc-ripem-msg-begin-line)
	   (setq start (point))
	   (mc-activate-passwd 'ripem)
	   (insert mc-ripem-passwd "\n")
	   (re-search-forward (concat "^" mc-ripem-msg-end-line))
	   (message "Decrypting...")
	   (setq retval (call-process-region start (point) mc-ripem-path t t
					     nil "-d" "-k" "-"))
	   (or mc-passwd-timeout (mc-deactivate-passwd))
	   (if (= retval 0)
	       t
	     (mc-temp-display start (point) "*ERROR*")
	     nil))
	  (t
	   (message "Found no encrypted message in this buffer.")
	   nil))))

;;}}}  
;;{{{ Signing

(defun mc-sign-message (&optional scheme)
  "*Clear sign the message using the given encryption SCHEME."
  (interactive
   (if current-prefix-arg
       (list (read-from-minibuffer "Encryption Scheme: " nil nil t))))
  (or scheme (setq scheme mc-default-scheme))
  (let (start retval command)
    (cond ((eq scheme 'pgp)
	   (goto-char (point-min))
	   (search-forward (concat "\n" mail-header-separator "\n"))
	   (setq start (point))
	   (mc-activate-passwd 'pgp)
	   (insert mc-pgp-passwd "\n")
	   (let ((process-environment 
		  (cons "PGPPASSFD=0" process-environment)))
	     (setq retval (call-process-region start (point-max) mc-pgp-path
					       t t nil "-fast" "+clearsig=on"
					       "+batchmode" "-u"
					       mc-pgp-user-id)))
	   (or mc-passwd-timeout (mc-deactivate-passwd))
	   (cond ((= 0 retval)
		  (goto-char start)
		  (search-forward "\nJust a moment....")
		  (mc-temp-display start (point)))
		 (t
		  (error "PGP signing failed. Use C-x u to undo."))))
	  ((eq scheme 'ripem)
	   (setq command (concat mc-ripem-path " -e -m mic-clear -k -"))
	   (goto-char (point-min))
	   (search-forward (concat "\n" mail-header-separator "\n"))
	   (setq start (point))
	   (mc-activate-passwd 'ripem)
	   (insert mc-ripem-passwd "\n")
	   (setq retval (call-process-region start (point-max) mc-ripem-path
					     t t nil "-e" "-m" "mic-clear"
					     "-k" "-"))
	   (or mc-passwd-timeout (mc-deactivate-passwd))
	   (if (/= 0 retval)
	       (error "RIPEM signing failed. Use C-x u to undo.")))
	  (t
	   (error "Encryption scheme %s not recognized" scheme)))))
	   
;;}}}
;;{{{ Signature verification

;;{{{ mc-verify-signature

(defun mc-verify-signature ()
  "*Verify the signature of whatever signed message is in the current
buffer, and give the result as a message in the minibuffer. Returns t
if the signature is verified."
  (interactive)
  (let (start buf msg retval)
    (goto-char (point-min))
    (cond ((re-search-forward (concat "^" mc-pgp-signed-begin-line) nil t)
	   (beginning-of-line)
	   (setq start (point))
	   (re-search-forward (concat "^" mc-pgp-signed-end-line))
	   (setq msg (buffer-substring start (point)))
	   (save-excursion
	     (set-buffer (generate-new-buffer "*Verification*"))
	     (insert msg)
	     (setq retval (call-process-region
			   (point-min) (point-max) mc-pgp-path t 
			   t nil "+batchmode" "-f"))
	     (if (/= retval 0)
		 (progn (mc-temp-display (point-min) (point-max) "*ERROR*")
			(kill-buffer (current-buffer))
			nil)
	       (goto-char (point-min))
	       (search-forward "Good signature")
	       (beginning-of-line)
	       (setq start (point))
	       (end-of-line)
	       (message (buffer-substring start (point)))
	       (kill-buffer (current-buffer))
	       t)))
	  ((re-search-forward (concat "^" mc-ripem-msg-begin-line) nil t)
	   (beginning-of-line)
	   (setq start (point))
	   (re-search-forward (concat "^" mc-ripem-msg-end-line))
	   (setq msg (buffer-substring start (point)))
	   (mc-activate-passwd 'ripem)
	   (save-excursion
	     (set-buffer (generate-new-buffer "*Verification*"))
	     (insert mc-ripem-passwd "\n")
	     (insert msg)
	     (message "Verifying...")
	     (setq retval (call-process-region (point-min) (point-max)
					       mc-ripem-path t t nil 
					       "-d" "-k" "-"))
	     (or mc-passwd-timeout (mc-deactivate-passwd))
	     (if (/= 0 retval)
		 (progn (goto-char (point-min))
			(message (buffer-substring (point) (progn
							     (end-of-line)
							     (point))))
			(kill-buffer (current-buffer))
			nil)
	       (message "RIPEM signature verified")
	       (kill-buffer (current-buffer))
	       t)))
	  (t
	   (message "Found no signed message in this buffer.")
	   nil))))

;;}}}

;;}}}
;;{{{ Key management

;;{{{ mc-insert-public-key

(defun mc-insert-public-key (&optional scheme)
  "*Insert your public key at the end of the current buffer."
  (interactive
   (if current-prefix-arg
       (list (read-from-minibuffer "Encryption Scheme: " nil nil t))))
  (or scheme (setq scheme mc-default-scheme))
  (let (command start pubkey)
    (goto-char (point-max))
    (if (not (bolp))
	(insert "\n"))
    (cond ((eq scheme 'pgp)
	   (setq command (concat mc-pgp-path " +batchmode -kxaf '"
				 mc-pgp-user-id "'"))
	   (setq start (point))
	   (shell-command command t)
	   (goto-char start)
	   (search-forward mc-pgp-key-begin-line)
	   (beginning-of-line)
	   (mc-temp-display start (point)))
	  ((eq scheme 'ripem)
	   (if (file-readable-p mc-ripem-pubkeyfile)
	       (save-excursion
		 (set-buffer (find-file-noselect mc-ripem-pubkeyfile))
		 (goto-char (point-min))
		 (if (search-forward mc-ripem-user-id nil t)
		     (progn
		       (search-backward mc-ripem-key-begin-line)
		       (setq start (point))
		       (search-forward mc-ripem-key-end-line)
		       (setq pubkey (buffer-substring start (point))))
		   (message "Couldn't find key for `%s' in file %s"
			    mc-ripem-user-id mc-ripem-pubkeyfile))
		 (kill-buffer (current-buffer)))
	     (error "Cannot read file %s for public key" mc-ripem-pubkeyfile))
	   (if pubkey
	       (insert pubkey)))
	  (t
	   (error "Encryption scheme %s not recognized" scheme)))))

;;}}}
;;{{{ mc-snarf-keys

(defun mc-snarf-keys ()
  "*Add any public keys in the buffer to your keyring."
  (interactive)
  (let (start buf user exists)
    (goto-char (point-min))
    (cond ((search-forward mc-pgp-key-begin-line nil t)
	   (setq buf (generate-new-buffer " *Key Temp*"))
	   (goto-char (match-beginning 0))
	   (call-process-region (point) (point-max) mc-pgp-path nil
				buf nil "+batchmode" "-kaf")
	   (save-excursion
	     (set-buffer buf)
	     (mc-temp-display (point-min) (point-max) "*Key Management*"))
	   (kill-buffer buf))
	  ((search-forward mc-ripem-key-begin-line nil t)
	   (goto-char (match-beginning 0))
	   (setq start (point))
	   ;; Get the user ID of the key being added.
	   (re-search-forward "^User:\s-*.*$" nil t)
	   (setq user (buffer-substring (match-beginning 0) (match-end 0)))

	   (search-forward mc-ripem-key-end-line)
	   (if (file-writable-p mc-ripem-pubkeyfile)
	       (progn
		 (save-excursion
		   (set-buffer (find-file-noselect mc-ripem-pubkeyfile))
		   (goto-char (point-min))
		   (if (search-forward user nil t)
		       (setq exists t))
		   (kill-buffer (current-buffer)))
		 (if (not exists)
		     (append-to-file start (point) mc-ripem-pubkeyfile)
		   (message "RIPEM public key for this user already exists.")))
	     (error "Can't write to file %s" mc-ripem-pubkeyfile)))
	  (t
	   (error "No public key in current buffer")))))

;;}}}

;;}}}
;;{{{ Mode specific functions

(defvar mc-modes-alist
  (list (cons 'rmail-mode (list 'mc-rmail-decrypt-message
				'mc-rmail-verify-signature))
	(cons 'vm-mode (list 'mc-vm-decrypt-message
			     'mc-vm-verify-signature))
	(cons 'mh-folder-mode (list 'mc-mh-decrypt-message
				    'mc-mh-verify-message
				    'mc-mh-snarf-keys))
	(cons 'gnus-summary-mode (list 'mc-gnus-summary-decrypt-message
				       'mc-gnus-summary-verify-signature
				       'mc-gnus-summary-snarf-keys)))
  "*Association list to specify mode specific functions for reading.
Entries are of the form (MODE . (DECRYPT VERIFY SNARF)).
The SNARF is optional and defaults to `mc-snarf-keys'.")

;;{{{ RMAIL
(defun mc-rmail-verify-signature ()
  "*Verify the signature in the current message."
  (interactive)
  (if (not (equal mode-name "RMAIL"))
      (error "mc-rmail-verify-signature called in a non-RMAIL buffer"))
  (if (mc-verify-signature)
      (rmail-add-label "verified")))

(defun mc-rmail-decrypt-message ()
  "*Decrypt the contents of this message"
  (interactive)
  (let ((oldbuf (current-buffer)))
    (if (not (equal mode-name "RMAIL"))
	(error "mc-rmail-decrypt-message called in a non-RMAIL buffer"))
    (rmail-edit-current-message)
    (cond ((not (mc-decrypt-message))
	   (rmail-abort-edit))
	  ((or mc-always-replace
	       (y-or-n-p "Replace encrypted message with decrypted? "))
	   (rmail-cease-edit)
	   (rmail-kill-label "edited")
	   (rmail-add-label "decrypted"))
	  (t
	   (let ((tmp (generate-new-buffer "*Mailcrypt Viewing*")))
	     (copy-to-buffer tmp (point-min) (point-max))
	     (rmail-abort-edit)
	     (switch-to-buffer tmp t)
	     (view-mode oldbuf 'kill-buffer))))))

;;}}}
;;{{{ VM
(defun mc-vm-verify-signature ()
  "*Verify the signature in the current VM message"
  (interactive)
  (if (interactive-p)
      (vm-follow-summary-cursor))
  (vm-select-folder-buffer)
  (vm-check-for-killed-summary)
  (vm-error-if-folder-empty)
  (mc-verify-signature))

(defun mc-vm-decrypt-message ()
  "*Decrypt the contents of the current VM message"
  (interactive)
  (let ((oldbuf (current-buffer)))
    (if (interactive-p)
	(vm-follow-summary-cursor))
    (vm-select-folder-buffer)
    (vm-check-for-killed-summary)
    (vm-error-if-folder-read-only)
    (vm-error-if-folder-empty)
    (vm-edit-message)
    (cond ((not (mc-decrypt-message))
	   (progn (message "Decryption failed.")
		  (vm-edit-message-abort)))
	  ((or mc-always-replace
	       (y-or-n-p "Replace encrypted message with decrypted? "))
	   (vm-edit-message-end))
	  (t
	   (let ((tmp (generate-new-buffer "*Mailcrypt Viewing*")))
	     (copy-to-buffer tmp (point-min) (point-max))
	     (vm-edit-message-abort)
	     (switch-to-buffer tmp t)
	     (view-mode oldbuf 'kill-buffer))))))
	   
;;}}}
;;{{{ GNUS
(defun mc-gnus-summary-verify-signature ()
  (interactive)
  (gnus-summary-select-article gnus-save-all-headers gnus-save-all-headers)
  (gnus-eval-in-buffer-window gnus-article-buffer
    (save-restriction (widen) (mc-verify-signature))))

(defun mc-gnus-summary-snarf-keys ()
  (interactive)
  (gnus-summary-select-article gnus-save-all-headers gnus-save-all-headers)
  (gnus-eval-in-buffer-window gnus-article-buffer
    (save-restriction (widen) (mc-snarf-keys))))

(defun mc-gnus-summary-decrypt-message ()
  (interactive)
  (gnus-summary-select-article gnus-save-all-headers gnus-save-all-headers)
  (gnus-eval-in-buffer-window gnus-article-buffer
    (save-restriction (widen) (mc-decrypt-message))))

;;}}}		
;;{{{ MH
(defun mc-mh-decrypt-message (decrypt-on-disk)
  "*Decrypt the contents of the current MH message in the show buffer. With
prefix arg, decrypt the message on disk as well."
  (interactive "P")
  (let* ((msg (mh-get-msg-num t))
	 (msg-filename (mh-msg-filename msg))
	 (show-buffer (get-buffer mh-show-buffer))
	 decrypt-okay)
    (setq decrypt-on-disk (or mc-always-replace decrypt-on-disk))
    (if decrypt-on-disk
	(progn
	  (save-excursion
	    (set-buffer (create-file-buffer msg-filename))
	    (insert-file-contents msg-filename t)
	    (if (setq decrypt-okay (mc-decrypt-message))
		(save-buffer)
	      (message "Decryption failed.")
	      (set-buffer-modified-p nil))
	    (kill-buffer nil))
	  (if decrypt-okay
	      (if (and show-buffer
		       (equal msg-filename (buffer-file-name show-buffer)))
		  (save-excursion
		    (save-window-excursion
		      (mh-invalidate-show-buffer)))))
	  (mh-show msg))
      (mh-show msg)
      (save-excursion
	(set-buffer mh-show-buffer)
	(if (setq decrypt-okay (mc-decrypt-message))
	    (progn
	      (goto-char (point-min))
	      (set-buffer-modified-p nil))
	  (message "Decryption failed.")))
      (if (not decrypt-okay)
	  (progn
	    (mh-invalidate-show-buffer)
	    (mh-show msg))))))

(defun mc-mh-verify-signature ()
  "*Verify the signature in the current MH message."
  (interactive)
  (let ((msg (mh-get-msg-num t)))
    (mh-show msg)
    (save-excursion
      (set-buffer mh-show-buffer)
      (mc-verify-signature))))

(defun mc-mh-snarf-keys ()
  (interactive)
  (mh-show (mh-get-msg-num t))
  (save-excursion
    (set-buffer mh-show-buffer)
    (mc-snarf-keys)))
;;}}}

;;}}}
;;{{{ Menubar stuff
(defun mc-create-read-menu-bar ()
  ;; Create a menu bar entry for reading modes.
  (let ((decrypt (nth 0 (cdr (assoc major-mode mc-modes-alist))))
	(verify (nth 1 (cdr (assoc major-mode mc-modes-alist))))
	(snarf (nth 2 (cdr (assoc major-mode mc-modes-alist)))))
    (if (not (and decrypt verify))
	(error "Decrypt and verify functions not defined for this major mode."))
    (if (not snarf)
	(setq snarf 'mc-snarf-keys))
    (if (string-match "Lucid" (emacs-version))
	(let ((x (list "Mailcrypt"
		       (vector "Decrypt Message" decrypt t)
		       (vector "Verify Signature" verify t)
		       (vector "Snarf Public Key" snarf t))))
	  (set-buffer-menubar current-menubar)
	  (add-menu nil "Mailcrypt" (cdr x)))
      (local-set-key [menu-bar mailcrypt]
		     (cons "Mailcrypt" (make-sparse-keymap "Mailcrypt")))
      (local-set-key [menu-bar mailcrypt decrypt]
		     (cons "Decrypt Message" decrypt))
      (local-set-key [menu-bar mailcrypt verify]
		     (cons "Verify Signature" verify))
      (local-set-key [menu-bar mailcrypt snarf]
		     (cons "Snarf Public Key" snarf)))))

(defun mc-create-write-menu-bar ()
  ;; Create a menu bar entry for writing modes.
  (if (string-match "Lucid" (emacs-version))
      (let ((x (list "Mailcrypt"
		     (vector "Encrypt Message" 'mc-encrypt-message t)
		     (vector "Sign Message" 'mc-sign-message t)
		     (vector "Insert Public Key" 'mc-insert-public-key t))))
	(set-buffer-menubar current-menubar)
	(add-menu nil "Mailcrypt" (cdr x)))
    (local-set-key [menu-bar mailcrypt]
		   (cons "Mailcrypt" (make-sparse-keymap "Mailcrypt")))
    (local-set-key [menu-bar mailcrypt encrypt]
		   (cons "Encrypt Message" 'mc-encrypt-message))
    (local-set-key [menu-bar mailcrypt sign]
		   (cons "Sign Message" 'mc-sign-message))
    (local-set-key [menu-bar mailcrypt insert]
		   (cons "Insert Public Key" 'mc-insert-public-key))))
;;}}}
(provide 'mailcrypt)


;; Local Variables:
;; folded-file: t
;; End:

