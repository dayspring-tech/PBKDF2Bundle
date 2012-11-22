Dayspring's PBKDF2 Bundle
=========================

This bundle provides a Symfony2 security implementation using PBKDF2 hashing.  
It also provides password validation against a list of known passwords.

Your database needs a weak_passwords table:

	CREATE TABLE `weak_passwords` (
	  `password` varchar(255) NOT NULL,
	  PRIMARY KEY  (`password`)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8;

Then load it with your favorite password list:

	LOAD DATA LOCAL INFILE '~/Downloads/cain.txt'
	INTO TABLE weak_passwords;
