<?php
/* Copyright (c) Rhapsody Project
 *
 * Licensed under the MIT License (http://opensource.org/licenses/MIT)
 *
 * Permission is hereby granted, free of charge, to any
 * person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the
 * Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice
 * shall be included in all copies or substantial portions of
 * the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
 * KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 * OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
 * OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
namespace Rhapsody\SecurityBundle\Tests\Functional\Dummy;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpKernel\Kernel;

/**
 * A kernel that can be used for testing.
 */
abstract class TestKernel extends Kernel
{
    private $testCase;
    private $rootConfig;

    public function __construct($testCase, $rootConfig, $environment, $debug)
    {
        $configPath = $this->getRootDir().'/config/'.$rootConfig;

        $fs = new Filesystem();
        if (!$fs->isAbsolutePath($rootConfig) && !is_file($configPath)) {
            throw new \InvalidArgumentException(sprintf('The root config "%s" does not exist.', $configPath));
        }
        $this->testCase = $testCase;
        $this->rootConfig = $configPath;

        parent::__construct($environment, $debug);
    }

    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        if (null === $this->name) {
            $this->name = parent::getName().md5($this->rootConfig);
        }

        return $this->name;
    }

    /**
     * {@inheritdoc}
     */
    public function getCacheDir()
    {
        return sys_get_temp_dir().'/'.Kernel::VERSION.'/'.$this->testCase.'/cache/'.$this->environment;
    }

    /**
     * {@inheritDoc}
     * @see \Symfony\Component\HttpKernel\Kernel::getKernelParameters()
     */
    protected function getKernelParameters()
    {
        $parameters = parent::getKernelParameters();
        $parameters['kernel.test_case'] = $this->testCase;
        return $parameters;
    }

    /**
     * {@inheritdoc}
     */
    public function getLogDir()
    {
        return sys_get_temp_dir().'/'.Kernel::VERSION.'/'.$this->testCase.'/logs';
    }

    /**
     * {@inheritdoc}
     */
    public function registerContainerConfiguration(LoaderInterface $loader)
    {
        $loader->load($this->rootConfig);
    }
}
