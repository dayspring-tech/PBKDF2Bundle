<?php
namespace Dayspring\PBKDF2Bundle\Command;

use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;

/**
 * Description of GenerateHashCommand
 *
 * @author jwong
 */
class GenerateHashCommand extends ContainerAwareCommand {
    protected function configure() {
		
		$this
			->setName('pbkdf2:hash')
			->setDescription('Hash a password')
            ->addArgument(
                'password',
                \Symfony\Component\Console\Input\InputArgument::REQUIRED,
                'What password do you want to hash?'
            );
    }
	
	
	protected function execute(\Symfony\Component\Console\Input\InputInterface $input, \Symfony\Component\Console\Output\OutputInterface $output) {
		$password = $input->getArgument('password');
		
		$passwordService = $this->getContainer()->get('password');
		
		list($salt, $hash, $iterations) = $passwordService->generatePasswordSaltHashAndIterations($password);
		
		$output->writeln(sprintf("Password:   %s", $password));
		$output->writeln(sprintf("Salt:       %s", $salt));
		$output->writeln(sprintf("Hash:       %s", $hash));
		$output->writeln(sprintf("Iterations: %s", $iterations));
	}
}

?>
