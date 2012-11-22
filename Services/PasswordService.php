<?php
namespace Dayspring\PBKDF2Bundle\Services;

use Symfony\Component\HttpKernel\Log\LoggerInterface;

/* 
 * PBKDF2-based Password hashing functions.
 * 
 * See also:
 * http://en.wikipedia.org/wiki/PBKDF2
 * http://www.f-secure.com/weblog/archives/00002095.html
 * http://tools.ietf.org/html/rfc2898
 */
class PasswordService {
    /**
     * Should old MD5-hashed passwords be accepted?
     */
    protected $allowOldPasswords;
	protected $md5BeforePbkdf2 = false;

    /**
     * Iterations should be set to a range such that the hash calculation takes
     * a non-trivial amount of time.  A good target is 100-250ms per calculation.
     * This parameter controls brute-force vulnerability almost more than the
     * choice of hash algorithim itself.
     */
    protected $_iterations_min = 19000;
    protected $_iterations_max = 21000;

    protected $_hashLengthBytes = 32;
    protected $_hashAlgo;

    protected $__time = 0;

    /**
     * Constructor.
     *
     * @param string $hashAlgorithm  The hashing algorithm to use.
     * @param array  $allowOldPasswords SHould old passwords be allowed.
     * @param LoggerInterface $logger Monolog logger to use for output.
     */
    public function __construct($hashAlgorithm = 'sha1', $allowOldPasswords = true, LoggerInterface $logger = null, $md5BeforePbkdf2 = false)
    {
        $this->logger = $logger;
        $this->_hashAlgo = $hashAlgorithm;
        $this->allowOldPasswords = $allowOldPasswords;
		$this->md5BeforePbkdf2 = $md5BeforePbkdf2;
		
		//$this->container->getParameter('dayspring_pbkdf2.md5_before_pbkdf2');
    }

   /**
     * Generate a random salt, random iteration count, then hash the provided password.
     * The returned values must be saved to the user record.
     * @param <type> $plaintext_password
     * @return <type> array (salt, hash, iterations)
     */
    public function generatePasswordSaltHashAndIterations($plaintext_password){
        $salt = $this->generateSalt();

        $iterations = mt_rand($this->_iterations_min, $this->_iterations_max);

        $hash = $this->hash_password($plaintext_password, $salt, $iterations);

        return array($salt, $hash, $iterations);
    }

    /**
     * Check if the provided password is correct.
     * @param <type> $plaintext_password
     * @param <type> $salt
     * @param <type> $hash
     * @param <type> $iterations
     * @return <type> True if correct, False otherwise.
     */
    public function checkPassword($plaintext_password, $salt, $hash, $iterations){
        if ($this->allowOldPasswords && strlen($hash) == 32 && empty($salt)){
            // old MD5-style password...
            return $plaintext_password == $hash;
        }

        $testHash = $this->hash_password($plaintext_password, $salt, $iterations);
        $this->logger->info($testHash);
        return $hash == $testHash;
    }


    /**
     * Run the PBKDF2 function using the configured derived hash length and hash algorithm.
     * @param <type> $password
     * @param <type> $salt
     * @param <type> $iterations
     * @return <type> Hex representation of the derived hash.
     */
    private function hash_password($password, $salt, $iterations){
        if (null !== $this->logger) {
            $this->__time = microtime(true);
        }
		if ($this->md5BeforePbkdf2){
			$password = md5($password);
		}
        $hash = bin2hex($this->pbkdf2($password, $salt, $iterations, $this->_hashLengthBytes, $this->_hashAlgo));
        if (null !== $this->logger) {
            $this->logger->notice(sprintf("hash took %f secs<br>\n", (microtime(true) - $this->__time)));
				}
        return $hash;
    }

    /**
     * Use SHA-256 to generate a 64-character salt.
     * @return <type> salt
     */
    private function generateSalt(){
        $t = mt_rand();
        $t .= microtime(true);

        return hash('sha256', $t);
    }

    /**
     * Implementation of the PBKDF2 key derivation function as described in RFC 2898.
     *
     * PBKDF2 was published as part of PKCS #5 v2.0 by RSA Security. The standard is
     * also documented in IETF RFC 2898.
     *
     * The first four function arguments are as the standard describes:
     *
     *     PBKDF2(P, S, c, dkLen)
     *
     * The fifth function argument specifies the hash function to be used. This should
     * be provided in the same format as used for the hash() function. The default
     * hash algorithm is SHA-1, but this is not recommended for new applications.
     *
     * The function returns false if dk_len is too large. Otherwise it returns the
     * derived key as a binary string.
     *
     * @author Henry Merriam <php@henrymerriam.com>
     *
     * @param    string    p        password
     * @param    string    s        salt
     * @param    int        c        iteration count
     * @param    int        dk_len    derived key length (octets)
     * @param    string    algo    hash algorithm
     *
     * @return    string            derived key
     */
    private function pbkdf2($p, $s, $c, $dk_len, $algo = 'sha1') {
        // experimentally determine h_len for the algorithm in question
        static $lengths;
        if (!isset($lengths[$algo])) { $lengths[$algo] = strlen(hash($algo, null, true)); }
        $h_len = $lengths[$algo];

        if ($dk_len > (pow(2, 32) - 1) * $h_len) {
            return false; // derived key is too long
        } else {
            $l = ceil($dk_len / $h_len); // number of derived key blocks to compute
            $t = null;
            for ($i = 1; $i <= $l; $i++) {
                $f = $u = hash_hmac($algo, $s . pack('N', $i), $p, true); // first iterate
                for ($j = 1; $j < $c; $j++) {
                    $f ^= ($u = hash_hmac($algo, $u, $p, true)); // xor each iterate
                }
                $t .= $f; // concatenate blocks of the derived key
            }
            return substr($t, 0, $dk_len); // return the derived key of correct length
        }

    }

}