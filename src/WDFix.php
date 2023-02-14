<?php
/*
 *    Copyright 2022 Jan Sohn / xxAROX
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 */
declare(strict_types=1);
namespace xxAROX\WDFix;
use Closure;
use JsonException;
use JsonMapper;
use JsonMapper_Exception;
use pocketmine\command\Command;
use pocketmine\command\CommandSender;
use pocketmine\event\Listener;
use pocketmine\event\server\DataPacketReceiveEvent;
use pocketmine\network\mcpe\handler\LoginPacketHandler;
use pocketmine\network\mcpe\JwtException;
use pocketmine\network\mcpe\JwtUtils;
use pocketmine\network\mcpe\NetworkSession;
use pocketmine\network\mcpe\protocol\LoginPacket;
use pocketmine\network\mcpe\protocol\types\login\ClientData;
use pocketmine\network\PacketHandlingException;
use pocketmine\permission\DefaultPermissions;
use pocketmine\permission\Permission;
use pocketmine\permission\PermissionManager;
use pocketmine\player\Player;
use pocketmine\player\PlayerInfo;
use pocketmine\player\XboxLivePlayerInfo;
use pocketmine\plugin\PluginBase;
use pocketmine\plugin\PluginDescription;
use pocketmine\plugin\PluginLoader;
use pocketmine\plugin\ResourceProvider;
use pocketmine\scheduler\AsyncTask;
use pocketmine\Server;
use pocketmine\utils\Internet;
use pocketmine\utils\SingletonTrait;
use pocketmine\utils\TextFormat;
use ReflectionClass;
use ReflectionProperty;
use Throwable;


/**
 * Class WaterdogExtrasLoginPacketHandler
 * @package xxAROX\WDFix
 * @author Jan Sohn / xxAROX
 * @date 10. August, 2022 - 18:25
 * @ide PhpStorm
 * @project WaterdogPE-LoginExteras-Fixer
 */
class WaterdogExtrasLoginPacketHandler extends LoginPacketHandler{
	public function __construct(Server $server, NetworkSession $session, string $Waterdog_XUID, string $Waterdog_IP){
		$playerInfoConsumer = Closure::bind(function (PlayerInfo $info) use ($session, $Waterdog_XUID, $Waterdog_IP): void{
			$session->ip = $Waterdog_IP;
			$session->info = $newInfo = new XboxLivePlayerInfo($Waterdog_XUID, $info->getUsername(), $info->getUuid(), $info->getSkin(), $info->getLocale(), $info->getExtraData());
			$session->logger->setPrefix($session->getLogPrefix());
			$session->logger->info("Player: " . TextFormat::AQUA . $info->getUsername() . TextFormat::RESET);
		}, $this, $session);
		$authCallback = Closure::bind(function (bool $isAuthenticated, bool $authRequired, ?string $error, ?string $clientPubKey) use ($session): void{
			$session->setAuthenticationStatus(true, $authRequired, $error, $clientPubKey);
		}, $this, $session);
		parent::__construct($server, $session, $playerInfoConsumer, $authCallback);
	}
	/**
	 * Function parseClientData
	 * @param string $clientDataJwt
	 * @return ClientData
	 */
	protected function parseClientData(string $clientDataJwt): ClientData{
		try {
			[, $clientDataClaims,] = JwtUtils::parse($clientDataJwt);
		} catch (JwtException $e) {
			throw PacketHandlingException::wrap($e);
		}
		$mapper = new JsonMapper;
		$mapper->bEnforceMapType = false;
		$mapper->bExceptionOnMissingData = true;
		$mapper->bExceptionOnUndefinedProperty = true;
		try {
			$clientDataProperties = array_map(fn (ReflectionProperty $property) => $property->getName(), (new ReflectionClass(ClientData::class))->getProperties());
			foreach ($clientDataClaims as $k => $v) {
				if (!in_array($k, $clientDataProperties)) unset($clientDataClaims[$k]);
			}
			unset($properties);
			$clientData = $mapper->map($clientDataClaims, new ClientData);
		} catch (JsonMapper_Exception $e) {
			throw PacketHandlingException::wrap($e);
		}
		return $clientData;
	}
}

/**
 * Class WDFix
 * @package xxAROX\WDFix
 * @author Jan Sohn / xxAROX
 * @date 17. Januar, 2022 - 22:52
 * @ide PhpStorm
 * @project WaterdogPE-LoginExtras-Fixer
 */
class WDFix extends PluginBase implements Listener{
	private static bool $PRODUCTION = true;

	use SingletonTrait{
		setInstance as private;
		reset as private;
	}


	/**
	 * WDFix constructor.
	 * @param PluginLoader $loader
	 * @param Server $server
	 * @param PluginDescription $description
	 * @param string $dataFolder
	 * @param string $file
	 * @param ResourceProvider $resourceProvider
	 */
	public function __construct(PluginLoader $loader, Server $server, PluginDescription $description, string $dataFolder, string $file, ResourceProvider $resourceProvider){
		parent::__construct($loader, $server, $description, $dataFolder, $file, $resourceProvider);
		self::setInstance($this);
		self::$PRODUCTION = !str_ends_with($description->getVersion(), "-dev");
	}



	/**
	 * Function onLoad
	 * @return void
	 */
	protected function onLoad(): void{
		$this->saveResource("config.yml");
	}

	/**
	 * Function onEnable
	 * @return void
	 */
	protected function onEnable(): void{
		$needServerRestart = false;
		if ($this->getServer()->getConfigGroup()->getPropertyBool("player.verify-xuid", true)) {
			$this->getLogger()->warning("§eMay {$this->getDescription()->getPrefix()} doesn't work correctly to prevent bugs set §f'§2player.verify-xuid§f' §ein §6pocketmine.yml §eto §f'§cfalse§f'");
			$needServerRestart = true;
		}
		if ($this->getServer()->getOnlineMode()) {
			$this->getLogger()->alert($this->getDescription()->getPrefix() . " is not compatible with online mode!");
			$this->getLogger()->warning("§ePlease set §f'§2xbox-auth§f' §ein §6server.properties §eto §f'§coff§f'");
			$needServerRestart = true;
		}
		if ($needServerRestart) $this->getLogger()->warning("Then restart the server!");
		else {
            $this->getServer()->getPluginManager()->registerEvents($this, $this);
            if ($this->getConfig()->get("force-players-to-waterdog", true)) {
                $this->getLogger()->alert("§cPlayers §nwill be kicked§r§c if they are not authenticated to §bWaterdog§3PE§c!§r");
            } else {
                $this->getLogger()->info("§aPlayers will §nnot§r§a be kicked if they are not authenticated to §bWaterdog§3PE§a!§r");
            }
        }
	}

	/**
	 * Function DataPacketReceiveEvent
	 * @param DataPacketReceiveEvent $event
	 * @return void
	 * @priority MONITOR
	 * @handleCancelled true
	 */
	public function DataPacketReceiveEvent(DataPacketReceiveEvent $event): void{
		$packet = $event->getPacket();
		if ($packet instanceof LoginPacket) {
			try {
				[, $clientData,] = JwtUtils::parse($packet->clientDataJwt);
			} catch (JwtException $e) {
				throw PacketHandlingException::wrap($e);
			}
			if (
				(
					!isset($clientData["Waterdog_XUID"])
					|| !isset($clientData["Waterdog_IP"])
                    // NOTE: Get ip-address provided from waterdog downstream connection
				)
				&& $this->getConfig()->get("force-players-to-waterdog", true)
			) {
				$event->getOrigin()->disconnect(str_replace("{PREFIX}", $this->getDescription()->getPrefix(), $this->getConfig()->get("kick-message", "§c{PREFIX}§e: §cNot authenticated to §bWaterdog§3PE§c!§f\n§cPlease connect to §3Waterdog§c!")));
				return;
			}
			if (isset($clientData["Waterdog_XUID"])) {
				$event->getOrigin()->setHandler(new WaterdogExtrasLoginPacketHandler(
					Server::getInstance(),
					$event->getOrigin(),
					$clientData["Waterdog_XUID"],
					$clientData["Waterdog_IP"]
				));
			}
			unset($clientData);
		}
	}

	/**
	 * Function checkIpAddress
	 * @param string $providedIpAddress
	 * @return bool
	 */
	private function checkIpAddress(string $providedIpAddress): bool{
		if (strtolower($providedIpAddress) === "localhost" || $providedIpAddress === "0.0.0.0") $providedIpAddress = "127.0.0.1";
		return $providedIpAddress == $this->getConfig()->get("waterdog-bind-address", "127.0.0.1");
	}

	/**
	 * Function applyVersionChanges
	 * @return void
	 */
	private function applyVersionChanges(): void{
		$config = $this->getConfig();
		$from = $config->get("config-version", "0.0.0");
		$current = explode("-", $this->getDescription()->getVersion())[0];

		if (version_compare($from, $current, ">=")) return;
		$config->set("config-version", $current);
		$this->getLogger()->notice("Updating config to newer version..");

		if (version_compare($from, "1.5.3", "<")) {
			$this->getLogger()->notice("Added documentation for config, delete the current and restart the server to apply documentations!");
			$config->set("force-players-to-waterdog", $config->get("kick-players-if-no-waterdog-information-was-found", true));
			$config->remove("kick-players-if-no-waterdog-information-was-found");
			$config->set("waterdog-bind-address", "127.0.0.1");
		}

		if ($config->hasChanged()) {
			try {
				$config->save();
			} catch (JsonException $exception) {
				$this->getLogger()->logException($exception);
			}
		}
		$this->getLogger()->info("§2Updated config to latest version!");
	}
}
