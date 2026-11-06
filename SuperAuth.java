package uz.jigar.superauth;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.Location;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.entity.EntityPickupItemEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.player.*;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;
import org.bukkit.scheduler.BukkitRunnable;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class SuperAuth extends JavaPlugin implements Listener {

    private final Set<UUID> authenticated = ConcurrentHashMap.newKeySet();
    private final Map<UUID, Long> joinTime = new HashMap<>();
    private final Map<String, Session> sessions = new HashMap<>();

    private final SecureRandom secureRandom = new SecureRandom();
    private File usersFile;
    private YamlConfiguration users;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        loadUsers();

        Bukkit.getPluginManager().registerEvents(this, this);

        new BukkitRunnable() {
            @Override
            public void run() {
                long now = System.currentTimeMillis();
                long maxTime = getConfig().getLong("settings.login-timeout-seconds", 60) * 1000L;

                for (Player player : Bukkit.getOnlinePlayers()) {
                    if (authenticated.contains(player.getUniqueId())) {
                        continue;
                    }

                    Long joined = joinTime.get(player.getUniqueId());
                    if (joined != null && now - joined > maxTime) {
                        player.kickPlayer(message("messages.timeout-kick"));
                        continue;
                    }

                    if (isRegistered(player.getName())) {
                        player.sendTitle(color("&e&lKIRISH"), color("&f/login <parol>"), 0, 40, 10);
                        player.sendMessage(message("messages.please-login"));
                    } else {
                        player.sendTitle(color("&a&lRO'YXATDAN O'TISH"),
                                color("&f/register <parol> <parol>"), 0, 40, 10);
                        player.sendMessage(message("messages.please-register"));
                    }
                }
            }
        }.runTaskTimer(this, 40L, 100L);

        getLogger().info("SuperAuth muvaffaqiyatli ishga tushdi!");
    }

    @Override
    public void onDisable() {
        saveUsers();
        authenticated.clear();
        joinTime.clear();
        sessions.clear();
    }

    private void loadUsers() {
        if (!getDataFolder().exists() && !getDataFolder().mkdirs()) {
            getLogger().severe("Plugin papkasini yaratib bo'lmadi!");
        }
        usersFile = new File(getDataFolder(), "users.yml");
        if (!usersFile.exists()) {
            try {
                if (!usersFile.createNewFile()) {
                    getLogger().warning("users.yml yaratilmadi.");
                }
            } catch (Exception exception) {
                getLogger().severe("users.yml yaratishda xato: " + exception.getMessage());
            }
        }
        users = YamlConfiguration.loadConfiguration(usersFile);
    }

    private void saveUsers() {
        if (users == null || usersFile == null) return;
        try {
            users.save(usersFile);
        } catch (Exception exception) {
            getLogger().severe("Foydalanuvchilarni saqlashda xato: " + exception.getMessage());
        }
    }

    private String message(String path) {
        String prefix = getConfig().getString("messages.prefix", "&8[&6SuperAuth&8] ");
        String text = getConfig().getString(path, "&c" + path);
        return color(prefix + text);
    }

    private String color(String text) {
        return ChatColor.translateAlternateColorCodes('&', text == null ? "" : text);
    }

    private boolean isRegistered(String playerName) {
        return users.contains("players." + playerName.toLowerCase());
    }

    private String createSalt() {
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private String hashPassword(String password, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] result = digest.digest((salt + password).getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(result);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 mavjud emas", exception);
        }
    }

    private void savePassword(String playerName, String password) {
        String key = "players." + playerName.toLowerCase();
        String salt = createSalt();
        users.set(key + ".name", playerName);
        users.set(key + ".salt", salt);
        users.set(key + ".password", hashPassword(password, salt));
        saveUsers();
    }

    private boolean checkPassword(String playerName, String password) {
        String key = "players." + playerName.toLowerCase();
        String salt = users.getString(key + ".salt");
        String storedHash = users.getString(key + ".password");

        if (salt == null || storedHash == null) return false;

        String enteredHash = hashPassword(password, salt);
        return MessageDigest.isEqual(
                storedHash.getBytes(StandardCharsets.UTF_8),
                enteredHash.getBytes(StandardCharsets.UTF_8)
        );
    }

    private void authenticate(Player player) {
        authenticated.add(player.getUniqueId());
        joinTime.remove(player.getUniqueId());
        player.removePotionEffect(PotionEffectType.BLINDNESS);
        player.removePotionEffect(PotionEffectType.SLOWNESS);
    }

    private String getPlayerIp(Player player) {
        return player.getAddress() == null
                ? ""
                : player.getAddress().getAddress().getHostAddress();
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        String ip = getPlayerIp(player);

        Session session = sessions.get(ip);
        long sessionTimeout = getConfig().getLong("settings.session-timeout-minutes", 10) * 60_000L;

        if (!ip.isEmpty() && session != null
                && session.playerName.equalsIgnoreCase(player.getName())
                && System.currentTimeMillis() - session.timestamp <= sessionTimeout) {
            authenticate(player);
            player.sendMessage(message("messages.session-restored"));
            return;
        }

        joinTime.put(player.getUniqueId(), System.currentTimeMillis());
        player.addPotionEffect(new PotionEffect(PotionEffectType.BLINDNESS, Integer.MAX_VALUE, 0, false, false));
        player.addPotionEffect(new PotionEffect(PotionEffectType.SLOWNESS, Integer.MAX_VALUE, 5, false, false));
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        Player player = event.getPlayer();

        if (authenticated.contains(player.getUniqueId())) {
            String ip = getPlayerIp(player);
            if (!ip.isEmpty()) {
                sessions.put(ip, new Session(player.getName(), System.currentTimeMillis()));
            }
        }

        authenticated.remove(player.getUniqueId());
        joinTime.remove(player.getUniqueId());
    }

    @EventHandler
    public void onMove(PlayerMoveEvent event) {
        if (authenticated.contains(event.getPlayer().getUniqueId()) || event.getTo() == null) return;

        Location from = event.getFrom();
        Location to = event.getTo();

        if (from.getX() != to.getX() || from.getY() != to.getY() || from.getZ() != to.getZ()) {
            event.setTo(from);
        }
    }

    @EventHandler
    public void onChat(AsyncPlayerChatEvent event) {
        if (!authenticated.contains(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
            event.getPlayer().sendMessage(message("messages.please-login"));
        }
    }

    @EventHandler
    public void onCommandPreprocess(PlayerCommandPreprocessEvent event) {
        if (authenticated.contains(event.getPlayer().getUniqueId())) return;

        String commandLine = event.getMessage().toLowerCase().trim();
        boolean allowed = commandLine.matches("^/(login|l)(\\s.*)?$")
                || commandLine.matches("^/(register|reg)(\\s.*)?$");

        if (!allowed) {
            event.setCancelled(true);
            event.getPlayer().sendMessage(message("messages.please-login"));
        }
    }

    @EventHandler
    public void onBreak(BlockBreakEvent event) {
        if (!authenticated.contains(event.getPlayer().getUniqueId())) event.setCancelled(true);
    }

    @EventHandler
    public void onPlace(BlockPlaceEvent event) {
        if (!authenticated.contains(event.getPlayer().getUniqueId())) event.setCancelled(true);
    }

    @EventHandler
    public void onDrop(PlayerDropItemEvent event) {
        if (!authenticated.contains(event.getPlayer().getUniqueId())) event.setCancelled(true);
    }

    @EventHandler
    public void onPickup(EntityPickupItemEvent event) {
        if (event.getEntity() instanceof Player player
                && !authenticated.contains(player.getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onDamage(EntityDamageEvent event) {
        if (event.getEntity() instanceof Player player
                && !authenticated.contains(player.getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onAttack(EntityDamageByEntityEvent event) {
        if (event.getDamager() instanceof Player player
                && !authenticated.contains(player.getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onInteract(PlayerInteractEvent event) {
        if (!authenticated.contains(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onInventoryClick(InventoryClickEvent event) {
        if (event.getWhoClicked() instanceof Player player
                && !authenticated.contains(player.getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        String cmd = command.getName().toLowerCase();

        if (cmd.equals("superauth")) {
            if (!sender.hasPermission("superauth.admin")) {
                sender.sendMessage(color("&cSizda ruxsat yo'q!"));
                return true;
            }
            if (args.length == 1 && args[0].equalsIgnoreCase("reload")) {
                reloadConfig();
                sender.sendMessage(color("&aSuperAuth konfiguratsiyasi qayta yuklandi."));
            } else {
                sender.sendMessage(color("&e/superauth reload &7- konfiguratsiyani yangilash"));
            }
            return true;
        }

        if (!(sender instanceof Player player)) {
            sender.sendMessage("Bu buyruq faqat o'yinchilar uchun!");
            return true;
        }

        UUID uuid = player.getUniqueId();

        if (cmd.equals("register") || cmd.equals("reg")) {
            if (authenticated.contains(uuid)) {
                player.sendMessage(message("messages.already-logged-in"));
                return true;
            }
            if (isRegistered(player.getName())) {
                player.sendMessage(message("messages.please-login"));
                return true;
            }
            if (args.length != 2) {
                player.sendMessage(color("&cIshlatish: /register <parol> <parolni_takrorlang>"));
                return true;
            }
            if (!args[0].equals(args[1])) {
                player.sendMessage(message("messages.passwords-dont-match"));
                return true;
            }

            int minLength = getConfig().getInt("settings.min-password-length", 4);
            int maxLength = getConfig().getInt("settings.max-password-length", 16);
            if (args[0].length() < minLength || args[0].length() > maxLength) {
                player.sendMessage(color("&cParol uzunligi " + minLength + " dan " + maxLength
                        + " tagacha bo'lishi kerak!"));
                return true;
            }

            savePassword(player.getName(), args[0]);
            authenticate(player);
            player.sendMessage(message("messages.register-success"));
            return true;
        }

        if (cmd.equals("login") || cmd.equals("l")) {
            if (authenticated.contains(uuid)) {
                player.sendMessage(message("messages.already-logged-in"));
                return true;
            }
            if (!isRegistered(player.getName())) {
                player.sendMessage(message("messages.please-register"));
                return true;
            }
            if (args.length != 1) {
                player.sendMessage(color("&cIshlatish: /login <parol>"));
                return true;
            }
            if (!checkPassword(player.getName(), args[0])) {
                player.sendMessage(message("messages.wrong-password"));
                return true;
            }

            authenticate(player);
            player.sendMessage(message("messages.login-success"));
            return true;
        }

        if (cmd.equals("changepassword")) {
            if (!authenticated.contains(uuid)) {
                player.sendMessage(message("messages.please-login"));
                return true;
            }
            if (args.length != 2) {
                player.sendMessage(color("&cIshlatish: /changepassword <eski_parol> <yangi_parol>"));
                return true;
            }
            if (!checkPassword(player.getName(), args[0])) {
                player.sendMessage(message("messages.wrong-password"));
                return true;
            }

            int minLength = getConfig().getInt("settings.min-password-length", 4);
            int maxLength = getConfig().getInt("settings.max-password-length", 16);
            if (args[1].length() < minLength || args[1].length() > maxLength) {
                player.sendMessage(color("&cYangi parol uzunligi " + minLength + " dan "
                        + maxLength + " tagacha bo'lishi kerak!"));
                return true;
            }

            savePassword(player.getName(), args[1]);
            player.sendMessage(color("&aParolingiz muvaffaqiyatli o'zgartirildi!"));
            return true;
        }

        return false;
    }

    private static final class Session {
        private final String playerName;
        private final long timestamp;

        private Session(String playerName, long timestamp) {
            this.playerName = playerName;
            this.timestamp = timestamp;
        }
    }
}
