<?php
namespace Dayspring\PBKDF2Bundle\Security\Authentication;

use DateTime;
use Dayspring\PBKDF2Bundle\Exception\IncompleteCredentialsException;
use Dayspring\PBKDF2Bundle\Security\Core\Authentication\Token\TOTPUsernamePasswordToken;
use Dayspring\PBKDF2Bundle\Security\Core\User\TOTPUserInterface;
use Dayspring\PBKDF2Bundle\Services\PasswordService;
use Dayspring\PBKDF2Bundle\Services\TOTPService;
use Symfony\Bridge\Monolog\Logger;
use Symfony\Component\Security\Core\Authentication\Provider\UserAuthenticationProvider;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class TOTPProvider extends UserAuthenticationProvider {
    private $logger;
    private $userProvider;
    
    private $passwordService;
	
	private $totpService;

    /**
     * Constructor.
     *
     * @param UserProviderInterface   $userProvider               An UserProviderInterface instance
     * @param UserCheckerInterface    $userChecker                An UserCheckerInterface instance
     * @param string                  $providerKey                The provider key
     * @param EncoderFactoryInterface $encoderFactory             An EncoderFactoryInterface instance
     * @param Boolean                 $hideUserNotFoundExceptions Whether to hide user not found exception or not
	 * @param PasswordService		  $passwordService			  PBKDF2 Encoding service
	 * @param TOTPService			  $totpService				  TOTP Service
     */
    public function __construct(UserProviderInterface $userProvider, UserCheckerInterface $userChecker, $providerKey, Logger $logger, $hideUserNotFoundExceptions = true, PasswordService $passwordService, TOTPService $totpService)
    {
$logger->info("construct TOTPProvider, userProvider: ".get_class($userProvider));        
        parent::__construct($userChecker, $providerKey, $hideUserNotFoundExceptions);

        $this->logger = $logger;
        $this->userProvider = $userProvider;
        
        $this->passwordService = $passwordService;
		
        $this->totpService = $totpService;
    }

    /**
     * {@inheritdoc}
     */
    protected function checkAuthentication(UserInterface $user, UsernamePasswordToken $token)
    {
        $this->logger->info('checkAuthentication');
        
        $currentUser = $token->getUser();
        if ($currentUser instanceof TOTPUserInterface) {
            if ($currentUser->getPassword() !== $user->getPassword()) {
                throw new BadCredentialsException('The credentials were changed from another session.');
            }
        } else {
            if (!$presentedPassword = $token->getCredentials()) {
                throw new BadCredentialsException('The presented password cannot be empty.');
            }

//            $this->logger->info(sprintf("checking user %s password: %s salt: %s hash: %s iter: %d\n",
//                $token->getUsername(), $presentedPassword, $user->getSalt(), $user->getPassword(), $user->getIterations()));
            
            $userPassword = $user->getPassword();
            if (empty($userPassword)) {
                throw new IncompleteCredentialsException('Authentication credentials are incomplete.');                
            }

                
            if (!$this->passwordService->checkPassword($presentedPassword, $user->getSalt(), $user->getPassword(), $user->getIterations())){
                throw new BadCredentialsException('The presented password is invalid.');                
            }
			
			if (!$this->totpService->checkToken($token->getToken(), $user->getValidTOTPSecrets())){
				throw new BadCredentialsException('The presented token is invalid.');
			}
        }
		
		$user->setLastLogin(new DateTime());
    }

    /**
     * {@inheritdoc}
     */
    protected function retrieveUser($username, UsernamePasswordToken $token)
    {
        $this->logger->info('retrieveUser');

        $user = $token->getUser();
        if ($user instanceof TOTPUserInterface) {
            return $user;
        }

        try {
            $user = $this->userProvider->loadUserByUsername($username);

            if (!$user instanceof TOTPUserInterface) {
                throw new AuthenticationServiceException('The user provider must return a TOTPUserInterface object.');
            }

            return $user;
        } catch (UsernameNotFoundException $notFound) {
            throw $notFound;
        } catch (\Exception $repositoryProblem) {
            throw new AuthenticationServiceException($repositoryProblem->getMessage(), 0, $repositoryProblem);
        }
    }
}

?>
