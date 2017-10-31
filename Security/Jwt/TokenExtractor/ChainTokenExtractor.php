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
namespace Rhapsody\SecurityBundle\Security\Jwt\TokenExtractor;

use Symfony\Component\HttpFoundation\Request;

/**
 * ChainTokenExtractor is the class responsible of extracting a JWT token
 * from a {@link Request} object using all mapped token extractors.
 *
 * Note: The extractor map is reinitialized to the configured extractors for
 * each different instance.
 *
 * @author Robin Chalas <robin.chalas@gmail.com>
 */
class ChainTokenExtractor implements \IteratorAggregate, TokenExtractorInterface
{
    /**
     * @var array
     */
    private $map;

    /**
     * @param array $map
     */
    public function __construct(array $map)
    {
        $this->map = $map;
    }

    /**
     * Adds a new token extractor to the map.
     *
     * @param TokenExtractorInterface $extractor
     */
    public function addExtractor(TokenExtractorInterface $extractor)
    {
        $this->map[] = $extractor;
    }

    /**
     * Removes a token extractor from the map.
     *
     * @param Closure $filter A function taking an extractor as argument,
     *                        used to find the extractor to remove,
     *
     * @return bool True in case of success, false otherwise
     */
    public function removeExtractor(\Closure $filter)
    {
        $filtered = array_filter($this->map, $filter);

        if (!$extractorToUnmap = current($filtered)) {
            return false;
        }

        $key = array_search($extractorToUnmap, $this->map);
        unset($this->map[$key]);

        return true;
    }

    /**
     * Clears the token extractor map.
     */
    public function clearMap()
    {
        $this->map = [];
    }

    /**
     * Iterates over the token extractors map calling {@see extract()}
     * until a token is found.
     *
     * {@inheritdoc}
     */
    public function extract(Request $request)
    {
        foreach ($this->getIterator() as $extractor) {
            if ($token = $extractor->extract($request)) {
                return $token;
            }
        }

        return false;
    }

    /**
     * Iterates over the mapped token extractors while generating them.
     *
     * An extractor is initialized only if we really need it (at
     * the corresponding iteration).
     *
     * @return \Generator The generated {@link TokenExtractorInterface} implementations
     */
    public function getIterator()
    {
        foreach ($this->map as $extractor) {
            if ($extractor instanceof TokenExtractorInterface) {
                yield $extractor;
            }
        }
    }
}
