<?php

namespace Dayspring\PBKDF2Bundle\Tests\Services;

use Dayspring\PBKDF2Bundle\Services\PasswordService;

class PasswordServiceTest extends \PHPUnit_Framework_TestCase {

    public function testCreatePassword() {
		$passwordService = $this->getPasswordService(false);
		
        $params = $passwordService->generatePasswordSaltHashAndIterations('password');
        $this->assertEquals(3, count($params), "Expect an array with three items");
        $this->assertTrue($passwordService->checkPassword('password', $params[0], $params[1], $params[2]));
        $this->assertFalse($passwordService->checkPassword('passw0rd', $params[0], $params[1], $params[2]));
    }

    public function testCreatePasswordMD5() {
		$passwordService = $this->getPasswordService(true);
		
        $params = $passwordService->generatePasswordSaltHashAndIterations('password');
        $this->assertEquals(3, count($params), "Expect an array with three items");
        $this->assertTrue($passwordService->checkPassword('password', $params[0], $params[1], $params[2]));
        $this->assertFalse($passwordService->checkPassword('passw0rd', $params[0], $params[1], $params[2]));
    }

    public function testCheckPassword() {
		$passwordService = $this->getPasswordService(false);
		
        $this->assertTrue($passwordService->checkPassword('password', 
                'b24a0d0634cc0997c15acf426254e0f058b45712b2fd11c9f45b52f08722580c', 
                'e6efd54654f1551faf1b45a2df8a8414c3062cd5153b31833eccd741609035dd', 
                19615));
		
        $this->assertFalse($passwordService->checkPassword('1234', 
                'e6375fb4e6ea5cdd2b6bc6a5d1c0a73c51b0d69ee38b143f0bb5e6771087500e',
                '0acff49c9bff30de7dd597dd1934797588cdcd768d820fe3efd82df6426bbaa8',
                19422));		
    }

    public function testCheckPasswordMD5() {
		$passwordService = $this->getPasswordService(true);
		
        $this->assertFalse($passwordService->checkPassword('password', 
                'b24a0d0634cc0997c15acf426254e0f058b45712b2fd11c9f45b52f08722580c', 
                'e6efd54654f1551faf1b45a2df8a8414c3062cd5153b31833eccd741609035dd', 
                19615));
		
        $this->assertTrue($passwordService->checkPassword('1234', 
                'e6375fb4e6ea5cdd2b6bc6a5d1c0a73c51b0d69ee38b143f0bb5e6771087500e',
                '0acff49c9bff30de7dd597dd1934797588cdcd768d820fe3efd82df6426bbaa8',
                19422));		
    }
	
	protected function getPasswordService($md5BeforePbkdf2) {
		$logger = $this->getMock('\Symfony\Component\HttpKernel\Log\LoggerInterface');
		return new PasswordService('sha1', true, $logger, $md5BeforePbkdf2);
	}
}