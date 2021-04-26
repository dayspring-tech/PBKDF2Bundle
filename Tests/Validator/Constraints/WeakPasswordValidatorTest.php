<?php
namespace Dayspring\PBKDF2Bundle\Tests\Validator\Constraints;

use Dayspring\PBKDF2Bundle\Framework\Test\DatabaseTestCase;
use Dayspring\PBKDF2Bundle\Validator\Constraints\WeakPassword;
use Dayspring\PBKDF2Bundle\Validator\Constraints\WeakPasswordValidator;


/**
 * Description of WeakPasswordValidatorTest
 *
 * @author jwong
 */
class WeakPasswordValidatorTest extends DatabaseTestCase {
	
    protected $validator;

    protected function setUp(): void
    {
		parent::setUp();
				
		$weakPasswordService = $this->createService('pbkdf2.weak_password');
        $this->validator = new WeakPasswordValidator($weakPasswordService);
    }

    protected function tearDown(): void
    {
        $this->validator = null;
    }

    public function testNullIsValid()
    {
        $this->assertTrue($this->validator->isValid(null, new WeakPassword()));
    }
	
    public function testPasswordIsNotValid()
    {
        $this->assertFalse($this->validator->isValid('password', new WeakPassword()));
        $this->assertFalse($this->validator->isValid('123456', new WeakPassword()));
    }
	
    public function testPasswordIsValid()
    {
        $this->assertTrue($this->validator->isValid('myverycomplexuniquepassword', new WeakPassword()));
    }
}

?>
