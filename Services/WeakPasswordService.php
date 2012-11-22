<?php
namespace Dayspring\PBKDF2Bundle\Services;

use Dayspring\PBKDF2Bundle\Model\WeakPasswordQuery;

/**
 * Description of WeakPasswordService
 *
 * @author jwong
 */
class WeakPasswordService {
	public function isWeakPassword($password){
		return WeakPasswordQuery::create()->findOneByPassword($password) != null;
	}
}

?>
