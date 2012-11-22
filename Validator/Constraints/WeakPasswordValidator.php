<?php
namespace Dayspring\PBKDF2Bundle\Validator\Constraints;

use Dayspring\PBKDF2Bundle\Services\WeakPasswordService;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;

/**
 * Description of WeakPasswordValidator
 *
 * @author jwong
 */
class WeakPasswordValidator extends ConstraintValidator {
	
	public function __construct(WeakPasswordService $weakPasswordService) {
		$this->weakPasswordService = $weakPasswordService;
	}
	
	public function isValid($value, Constraint $constraint){
        if ($this->weakPasswordService->isWeakPassword($value)) {
            $this->setMessage($constraint->message, array('%string%' => $value));
			return false;
        }
		return true;
    }
	
}

?>
