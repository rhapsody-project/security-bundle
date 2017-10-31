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
namespace Rhapsody\SecurityBundle\Tests\Functional;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase as BaseWebTestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpKernel\Kernel;

class WebTestCase extends BaseWebTestCase
{

    /**
     * The map of kernel classes
     * @var array
     */
    private static $kernelClassMap = array();

    private static $kernelRequirePathMap = array();

    /**
     * The namespace prefix for kernel classes.
     * @var string
     */
    private static $nsPrefix = 'Rhapsody\SecurityBundle\Tests\Functional\Dummy';

    public static function assertRedirect($response, $location)
    {
        self::assertTrue($response->isRedirect(), 'Response is not a redirect, got status code: '.substr($response, 0, 2000));
        self::assertEquals('http://localhost'.$location, $response->headers->get('Location'));

    }

    protected static function createKernel(array $options = array())
    {
        if (!isset($options['test_case'])) {
            throw new \InvalidArgumentException('The option "test_case" must be set.');
        }

        $testCase = $options['test_case'];
        $class = self::getKernelClassFor($testCase);

        $normalizedTestCase = self::normalizeTestCaseName($testCase);
        return new $class(
            $normalizedTestCase,
            isset($options['root_config']) ? $options['root_config'] : 'config.yml',
            isset($options['environment']) ? $options['environment'] : 'rhapsodysecuritybundletest'.$normalizedTestCase,
            isset($options['debug']) ? $options['debug'] : true
        );
    }

    protected static function deleteTmpDir($testCase)
    {
        $normalizedTestCase = self::normalizeTestCaseName($testCase);
        if (!file_exists($dir = sys_get_temp_dir().'/'.Kernel::VERSION.'/'.$normalizedTestCase)) {
            return;
        }
        $fs = new Filesystem();
        $fs->remove($dir);
    }

    protected static function getKernelClassFor($testCase)
    {
        if (!array_key_exists($testCase, self::$kernelRequirePathMap)) {
            $msg = sprintf('Unable to path find entry for: "%s". Registered path keys are: %s',
                $testCase, implode(',', array_keys(self::$kernelRequirePathMap)));
            throw new \OutOfBoundsException($msg);
        }

        if (!array_key_exists($testCase, self::$kernelClassMap)) {
            $msg = sprintf('Unable to find class entry for: "%s". Registered class keys are: %s',
                $testCase, implode(',', array_keys(self::$kernelClassMap)));
            throw new \OutOfBoundsException($msg);
        }

        require_once self::$kernelRequirePathMap[$testCase];
        return self::$kernelClassMap[$testCase];
    }

    /**
     * Returns the list of classes for configured dummy applications that can
     * (and should) be used for testing functionality.
     *
     * @return string[]
     */
    private static function getKernelClassMap()
    {
        return array(
            'jwt/FormLogin'  => self::$nsPrefix.'\Jwt\FormLogin\app\AppKernel',
            'jwt/JsonLogin'  => self::$nsPrefix.'\Jwt\JsonLogin\app\AppKernel',
            'jwt/JwtLogin'   => self::$nsPrefix.'\Jwt\JwtLogin\app\AppKernel',
            'jwt/JwtRefresh' => self::$nsPrefix.'\Jwt\JwtRefresh\app\AppKernel',
        );
    }

    /**
     * Returns the list of requirement paths for configured dummy applications
     * that can (and should) be used for testing functionality.
     *
     * @return string[]
     */
    private static function getKernelRequirePathMap()
    {
        return array(
            'jwt/FormLogin'  => __DIR__.'/Dummy/Jwt/FormLogin/app/AppKernel.php',
            'jwt/JsonLogin'  => __DIR__.'/Dummy/Jwt/JsonLogin/app/AppKernel.php',
            'jwt/JwtLogin'   => __DIR__.'/Dummy/Jwt/JwtLogin/app/AppKernel.php',
            'jwt/JwtRefresh' => __DIR__.'/Dummy/Jwt/JwtRefresh/app/AppKernel.php',
        );
    }

    private static function normalizeTestCaseName($testCase)
    {
        return strtolower(preg_replace(array('(\W)', '(\s)'), '_', $testCase));
    }

    /**
     * {@inheritDoc}
     */
    public static function setUpBeforeClass()
    {
        self::$kernelClassMap = self::getKernelClassMap();
        self::$kernelRequirePathMap = self::getKernelRequirePathMap();

        parent::setUpBeforeClass();
    }
}
