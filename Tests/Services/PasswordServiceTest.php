<?php

namespace Dayspring\PBKDF2Bundle\Tests\Services;

class PasswordServiceTest extends \Dayspring\PBKDF2Bundle\Framework\Test\DatabaseTestCase {

    public function testCreatePassword() {
        $passwordService = $this->createService('password');

        $params = $passwordService->generatePasswordSaltHashAndIterations('password');
        $this->assertEquals(3, count($params), "Expect an array with three items");
        $this->assertTrue($passwordService->checkPassword('password', $params[0], $params[1], $params[2]));
    }

    public function testCheckPassword() {
        $passwordService = $this->createService('password');

        $this->assertTrue($passwordService->checkPassword('password', 
                'b24a0d0634cc0997c15acf426254e0f058b45712b2fd11c9f45b52f08722580c', 
                'e6efd54654f1551faf1b45a2df8a8414c3062cd5153b31833eccd741609035dd', 
                19615));
    }

    public function testCheckPassword2() {
        $passwordService = $this->createService('password');

        $this->assertTrue($passwordService->checkPassword(md5('1234'), 
                'e6375fb4e6ea5cdd2b6bc6a5d1c0a73c51b0d69ee38b143f0bb5e6771087500e',
                '0acff49c9bff30de7dd597dd1934797588cdcd768d820fe3efd82df6426bbaa8',
                19422));

    }
}