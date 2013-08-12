<?php
namespace Dayspring\PBKDF2Bundle\Security\Authentication;

use Symfony\Component\Security\Core\Authentication\Provider\UserAuthenticationProvider;
use Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

use Symfony\Bridge\Monolog\Logger;

use Dayspring\PBKDF2Bundle\Services\PasswordService;
use Dayspring\PBKDF2Bundle\Security\Core\User\PBKDF2UserInterface;
use Dayspring\PBKDF2Bundle\Exception\IncompleteCredentialsException;

class PBKDF2Provider extends UserAuthenticationProvider {
    private $logger;
    private $userProvider;
    
    private $passwordService;

    /**
     * Constructor.
     *
     * @param UserProviderInterface   $userProvider               An UserProviderInterface instance
     * @param UserCheckerInterface    $userChecker                An UserCheckerInterface instance
     * @param string                  $providerKey                The provider key
     * @param EncoderFactoryInterface $encoderFactory             An EncoderFactoryInterface instance
     * @param Boolean                 $hideUserNotFoundExceptions Whether to hide user not found exception or not
     */
    public function __construct(UserProviderInterface $userProvider, UserCheckerInterface $userChecker, $providerKey, Logger $logger, $hideUserNotFoundExceptions = true, PasswordService $passwordService)
    {
$logger->info("construct PBKDF2Provider, userProvider: ".get_class($userProvider));        
        parent::__construct($userChecker, $providerKey, $hideUserNotFoundExceptions);

        $this->logger = $logger;
        $this->userProvider = $userProvider;
        
        $this->passwordService = $passwordService;
    }

    /**
     * {@inheritdoc}
     */
    protected function checkAuthentication(UserInterface $user, UsernamePasswordToken $token)
    {
        $this->logger->info('checkAuthentication');
        
        $currentUser = $token->getUser();
        if ($currentUser instanceof PBKDF2UserInterface) {
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
        }
		
		$user->setLastLogin(new \DateTime());
    }

    /**
     * {@inheritdoc}
     */
    protected function retrieveUser($username, UsernamePasswordToken $token)
    {
        $this->logger->info('retrieveUser');

        $user = $token->getUser();
        if ($user instanceof PBKDF2UserInterface) {
            return $user;
        }

        try {
            $user = $this->userProvider->loadUserByUsername($username);

            if (!$user instanceof PBKDF2UserInterface) {
                throw new AuthenticationServiceException('The user provider must return a PBKDF2UserInterface object.');
            }

            return $user;
        } catch (UsernameNotFoundException $notFound) {
            throw $notFound;
        } catch (\Exception $repositoryProblem) {
            throw new AuthenticationServiceException($repositoryProblem->getMessage(), $token, 0, $repositoryProblem);
        }
    }
}

?>
