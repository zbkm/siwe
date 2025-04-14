<?php
declare(strict_types=1);

use Zbkm\Siwe\SiweMessage;
use Zbkm\Siwe\SiweMessageParamsBuilder;

require_once "./../vendor/autoload.php";

session_start();
header("Content-Type: application/json");

$requestData = json_decode(file_get_contents('php://input'), true);


switch ($_GET["action"] ?? "") {
    case "profile":
        if (isset($_SESSION["authorized"]) && $_SESSION["authorized"]) {
            echo json_encode(["status" => "success", "profile" => ["address" => $_SESSION["params"]->address]]);
        } else {
            echo json_encode(["status" => "error", "message" => "Unauthorized"]);
        }
        break;

    case "logout":
        // !!! This code is provided as an example, it should not be used in production
        unset($_SESSION["authorized"]);
        echo json_encode(["status" => "success", "message" => "Logged out"]);
        break;

    case "get_siwe_message":
        $address = $requestData["address"] ?? null;
        if (!$address) {
            echo json_encode(["status" => "error", "message" => "Address is required"]);
            exit;
        }
        // create siwe message params
        $params = SiweMessageParamsBuilder::create()
            ->withAddress($address)
            ->withChainId(1)
            ->withNotBefore((new DateTime())->add(new DateInterval('PT5M')))
            // If nonce is not specified, it will be generated automatically.
            // ->withNonce(NonceManager::generate())
            ->withDomain($_SERVER["HTTP_HOST"])
            ->withUri("https://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]")
            ->build();
        $message = SiweMessage::create($params);

        // save params or message, to then use this data to verify the signature
        $_SESSION["params"] = $params;
        echo json_encode(["status" => "success", "siwe_message" => $message]);
        break;

    case "authorize":
        $signature = $requestData["signature"] ?? null;

        if (!$signature) {
            echo json_encode(["status" => "error", "message" => "Signature are required"]);
            exit;
        }

        if (!isset($_SESSION["params"])) {
            echo json_encode(["status" => "error", "message" => "SIWE message was not requested"]);
            exit;
        }

        // We use the previously generated message and the signature received from the user for verification
        // or SiweMessage::verifyMessage if you save message
        if (SiweMessage::verify($_SESSION["params"], $signature)) {
            // Authorization success
            $_SESSION["authorized"] = true;
            echo json_encode(["status" => "success", "message" => "Authorized"]);
        } else {
            // Authorization failed (signature invalid)
            echo json_encode(["status" => "error", "message" => "Invalid signature"]);
        }
        break;

    default:
        echo json_encode(["status" => "error", "message" => "Invalid action"]);
        break;
}

