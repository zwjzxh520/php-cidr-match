<?php
namespace CIDRmatch;

/** CIDR match
 * ================================================================================
 * IDRmatch is a library to match an IP to an IP range in CIDR notation (IPv4 and
 * IPv6).
 *  ================================================================================
 * @package     CIDRmatch
 * @author      Thomas Lutz
 * @copyright   Copyright (c) 2015 - present Thomas Lutz
 * @license     http://tholu.mit-license.org
 *  ================================================================================
 */

class CIDRmatch
{

    static public function match($ip, $cidr)
    {
        $c = explode('/', $cidr);
        $subnet = isset($c[0]) ? $c[0] : NULL;
        $mask = isset($c[1]) ? $c[1] : NULL;
        if ($mask === null) {
            $mask = 32;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // it's valid
            $ipVersion = 'v4';
        } else {
            // it's not valid
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                // it's valid
                $ipVersion = 'v6';
            } else {
                // it's not valid
                return false;
            }
        }
        if ($ip === $cidr) {
            return true;
        }

        switch ($ipVersion) {
            case 'v4':
                return static::IPv4Match($ip, $subnet, $mask);
                break;
            case 'v6':
                return static::IPv6Match($ip, $subnet, $mask);
                break;
        }
    }

    // inspired by: http://stackoverflow.com/questions/7951061/matching-ipv6-address-to-a-cidr-subnet
    static private function IPv6MaskToByteArray($subnetMask)
    {
        $addr = str_repeat("f", $subnetMask / 4);
        switch ($subnetMask % 4) {
            case 0:
                break;
            case 1:
                $addr .= "8";
                break;
            case 2:
                $addr .= "c";
                break;
            case 3:
                $addr .= "e";
                break;
        }
        $addr = str_pad($addr, 32, '0');
        $addr = pack("H*", $addr);

        return $addr;
    }

    // inspired by: http://stackoverflow.com/questions/7951061/matching-ipv6-address-to-a-cidr-subnet
    static public function IPv6Match($address, $subnetAddress, $subnetMask)
    {
        $rangeArr = array_map('trim', explode('-', $subnetAddress));
        $isRange = count($rangeArr) === 2;
        if ($isRange) {
            list($subnetAddress, $subnetAddress2) = $rangeArr;
        }
        if (!filter_var($subnetAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) || $subnetMask === NULL || $subnetMask === "" || $subnetMask < 0 || $subnetMask > 128) {
            return false;
        }
        if ($isRange && !filter_var($subnetAddress2, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return false;
        }
        $subnet = inet_pton($subnetAddress);
        $addr = inet_pton($address);
        if ($isRange) {
            $subnet2 = inet_pton($subnetAddress2);
            return $addr >= $subnet && $addr <= $subnet2;
        }

        $binMask = static::IPv6MaskToByteArray($subnetMask);

        return ($addr & $binMask) == $subnet;
    }

    // inspired by: http://stackoverflow.com/questions/594112/matching-an-ip-to-a-cidr-mask-in-php5
    static public function IPv4Match($address, $subnetAddress, $subnetMask)
    {

        $rangeArr = array_map('trim', explode('-', $subnetAddress));
        $isRange = count($rangeArr) === 2;
        if ($isRange) {
            list($subnetAddress, $subnetAddress2) = $rangeArr;
        }

        if (!filter_var($subnetAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || $subnetMask === NULL || $subnetMask === "" || $subnetMask < 0 || $subnetMask > 32) {
            return false;
        }
        if ($isRange && !filter_var($subnetAddress2, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        $address = ip2long($address);
        $subnetAddress = ip2long($subnetAddress);

        if ($isRange) {
            $subnet2 = ip2long($subnetAddress2);
            return $address >= $subnetAddress && $address <= $subnet2;
        }

        $mask = -1 << (32 - $subnetMask);
        $subnetAddress &= $mask; # nb: in case the supplied subnet wasn't correctly aligned
        return ($address & $mask) == $subnetAddress;
    }

}
