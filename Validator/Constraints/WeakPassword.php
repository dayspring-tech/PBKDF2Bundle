<?php
namespace Dayspring\PBKDF2Bundle\Validator\Constraints;


use Symfony\Component\Validator\Constraint;

/**
 * Checks the password against a list of known weak passwords
 *
 * @Annotation
 * 
 * @author jwong
 */
class WeakPassword extends Constraint {
	
	public $message = '"%string%" is not an acceptable password because it is in a known password list.';
	
	public function validatedBy(){
		return 'weak_password';
	}
}

?>
