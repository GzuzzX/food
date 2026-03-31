-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Mar 31, 2026 at 11:25 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `happyfood`
--

DELIMITER $$
--
-- Procedures
--
CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_pay_order` (IN `p_order_id` VARCHAR(20), IN `p_method` VARCHAR(20))   BEGIN
  DECLARE v_table_id VARCHAR(5);
  DECLARE v_subtotal  DECIMAL(10,2);
  DECLARE v_vat       DECIMAL(10,2);
  DECLARE v_total     DECIMAL(10,2);

  UPDATE orders
  SET is_paid = 1, status = 'paid', payment_method = p_method, paid_at = NOW()
  WHERE id = p_order_id;

  SELECT table_id, subtotal, vat_amount, total
  INTO v_table_id, v_subtotal, v_vat, v_total
  FROM orders WHERE id = p_order_id;

  INSERT IGNORE INTO sales (order_id, table_id, subtotal, vat_amount, total, payment_method)
  VALUES (p_order_id, v_table_id, v_subtotal, v_vat, v_total, p_method);
END$$

DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `cook_ids`
--

CREATE TABLE `cook_ids` (
  `id` varchar(20) NOT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` date NOT NULL DEFAULT curdate()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `customer_sessions`
--

CREATE TABLE `customer_sessions` (
  `session_id` varchar(36) NOT NULL,
  `table_id` varchar(5) NOT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `ended_at` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `customer_sessions`
--

INSERT INTO `customer_sessions` (`session_id`, `table_id`, `is_active`, `created_at`, `ended_at`) VALUES
('0e438573-1e04-4de7-a246-ed204854459d', '02', 0, '2026-03-30 22:31:08', '2026-04-01 00:13:01'),
('168979b6-ebf1-4946-918d-17217c2c9921', '01', 0, '2026-03-30 20:50:37', '2026-03-30 20:50:46'),
('264e33aa-0450-4614-b224-a62fc955a398', '02', 0, '2026-03-30 22:21:29', '2026-03-30 22:26:24'),
('26f2eca5-d3a9-4115-bd11-0a85bcc3464d', '01', 0, '2026-03-30 20:47:26', '2026-03-30 20:47:48'),
('2f86da32-8456-4a90-9a5d-d7083581d4ba', '01', 0, '2026-04-01 00:28:02', '2026-04-01 00:28:43'),
('3061faac-0d21-4728-b18e-9767361b7662', '01', 0, '2026-03-30 21:05:23', '2026-03-30 21:05:32'),
('33cfe642-c70d-4723-84a7-3adf8a657ebb', '01', 0, '2026-03-30 21:05:46', '2026-03-30 21:05:55'),
('3c21fe42-6641-45e2-8f9e-3250b627d275', '01', 0, '2026-03-30 22:10:31', '2026-03-30 22:10:39'),
('4580eff5-6429-4139-b67b-cccec79aff6f', '01', 0, '2026-03-30 21:39:27', '2026-03-30 21:39:51'),
('539d0c05-3c73-4222-a0d6-f877a0d34ab3', '02', 0, '2026-03-30 22:14:09', '2026-03-30 22:17:08'),
('6019f982-822e-4c9b-88e3-65cf69f0b69c', '02', 0, '2026-03-30 22:13:52', '2026-03-30 22:14:04'),
('6ac1ea9f-373c-4c79-ab3d-bd388acbb383', '02', 0, '2026-03-30 22:17:20', '2026-03-30 22:17:24'),
('87eaeb4f-fdc1-4ef9-8f8b-cd5097d18397', '01', 0, '2026-03-30 20:47:53', '2026-03-30 20:48:06'),
('88fde036-3b66-4038-a00a-e7c6303db1f0', '02', 0, '2026-03-30 20:51:16', '2026-03-30 20:51:26'),
('8d677588-74cb-4900-a18c-3135ed168e9e', '01', 0, '2026-03-30 20:43:27', '2026-03-30 20:47:24'),
('ae4fba19-08ba-4f6f-b623-bc814e2b2032', '01', 0, '2026-03-30 22:13:24', '2026-03-30 22:13:27'),
('c1b6b6e5-9405-49a3-a0db-777977ddcb97', '01', 0, '2026-03-30 22:26:36', '2026-03-30 22:31:04');

-- --------------------------------------------------------

--
-- Table structure for table `menu_categories`
--

CREATE TABLE `menu_categories` (
  `id` tinyint(4) NOT NULL,
  `code` varchar(20) NOT NULL,
  `name_th` varchar(50) NOT NULL,
  `name_en` varchar(50) NOT NULL,
  `sort_order` tinyint(4) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `menu_categories`
--

INSERT INTO `menu_categories` (`id`, `code`, `name_th`, `name_en`, `sort_order`) VALUES
(1, 'rice', 'จานเดียว', 'Main Course', 1),
(2, 'noodle', 'อาหารเส้น', 'Noodles', 2),
(3, 'drink', 'เครื่องดื่ม', 'Drinks', 3),
(4, 'dessert', 'ของหวาน', 'Desserts', 4);

-- --------------------------------------------------------

--
-- Table structure for table `menu_items`
--

CREATE TABLE `menu_items` (
  `id` varchar(20) NOT NULL,
  `category_id` tinyint(4) NOT NULL,
  `name_th` varchar(100) NOT NULL,
  `name_en` varchar(100) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `price` decimal(8,2) NOT NULL,
  `emoji` varchar(10) DEFAULT '?️',
  `image_url` varchar(255) DEFAULT NULL,
  `is_available` tinyint(1) NOT NULL DEFAULT 1,
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `menu_items`
--

INSERT INTO `menu_items` (`id`, `category_id`, `name_th`, `name_en`, `description`, `price`, `emoji`, `image_url`, `is_available`, `is_deleted`, `created_at`, `updated_at`) VALUES
('MN-001', 1, 'กะเพราหมูสับ', 'Basil Pork Rice', NULL, 60.00, '🍛', NULL, 1, 0, '2026-03-30 13:41:19', '2026-03-30 21:16:04'),
('MN-002', 2, 'ผัดไทยกุ้งสด', 'Pad Thai Shrimp', NULL, 80.00, '🍜', NULL, 1, 0, '2026-03-30 13:41:19', '2026-03-30 13:41:19'),
('MN-003', 1, 'ข้าวผัดปู', 'Crab Fried Rice', NULL, 90.00, '🦀', NULL, 1, 0, '2026-03-30 13:41:19', '2026-03-30 13:41:19'),
('MN-004', 1, 'ราดหน้าหมูนุ่ม', 'Pork Gravy Noodle', NULL, 70.00, '🍚', NULL, 1, 0, '2026-03-30 13:41:19', '2026-03-30 13:41:19'),
('MN-005', 2, 'บะหมี่หมูแดง', 'Red Pork Noodle', NULL, 65.00, '🍝', NULL, 1, 0, '2026-03-30 13:41:19', '2026-03-30 13:41:19'),
('MN-006', 1, 'ต้มยำกุ้งน้ำข้น', 'Tom Yum Kung', NULL, 120.00, '🍲', NULL, 1, 0, '2026-03-30 13:41:19', '2026-03-30 13:41:19'),
('MN-007', 3, 'ชาไทยเย็น', 'Thai Iced Tea', NULL, 45.00, '🧋', NULL, 1, 0, '2026-03-30 13:41:19', '2026-03-30 13:41:19'),
('MN-008', 3, 'น้ำมะนาวโซดา', 'Lemon Soda', NULL, 35.00, '🍋', NULL, 1, 0, '2026-03-30 13:41:19', '2026-03-30 13:41:19'),
('MN-009', 3, 'น้ำเปล่า', 'Water', NULL, 15.00, '💧', NULL, 1, 0, '2026-03-30 13:41:19', '2026-03-30 13:41:19'),
('MN-010', 4, 'ข้าวเหนียวมะม่วง', 'Mango Sticky Rice', NULL, 80.00, '🥭', NULL, 1, 0, '2026-03-30 13:41:19', '2026-03-30 13:41:19'),
('MN-011', 4, 'บัวลอยไข่หวาน', 'Bua Loi', NULL, 45.00, '🍡', NULL, 1, 0, '2026-03-30 13:41:19', '2026-03-30 13:41:19'),
('MN-012', 4, 'โรตีกล้วยนม', 'Banana Roti', NULL, 55.00, '🫓', NULL, 1, 0, '2026-03-30 13:41:19', '2026-03-30 13:41:19');

-- --------------------------------------------------------

--
-- Table structure for table `menu_toppings`
--

CREATE TABLE `menu_toppings` (
  `id` int(11) NOT NULL,
  `menu_id` varchar(20) NOT NULL,
  `name_th` varchar(80) NOT NULL,
  `extra_price` decimal(6,2) NOT NULL DEFAULT 0.00,
  `sort_order` tinyint(4) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `menu_toppings`
--

INSERT INTO `menu_toppings` (`id`, `menu_id`, `name_th`, `extra_price`, `sort_order`) VALUES
(1, 'MN-001', 'ไข่ดาว', 10.00, 1),
(2, 'MN-001', 'ข้าวเพิ่ม', 10.00, 2),
(3, 'MN-001', 'หมูพิเศษ', 20.00, 3),
(4, 'MN-002', 'กุ้งพิเศษ', 30.00, 1),
(5, 'MN-002', 'เส้นเพิ่ม', 10.00, 2),
(6, 'MN-003', 'ไข่ดาว', 10.00, 1),
(7, 'MN-003', 'ปูพิเศษ', 30.00, 2),
(8, 'MN-004', 'เส้นใหญ่', 0.00, 1),
(9, 'MN-004', 'เส้นเล็ก', 0.00, 2),
(10, 'MN-004', 'ข้าว', 0.00, 3),
(11, 'MN-005', 'ลูกชิ้น', 15.00, 1),
(12, 'MN-005', 'หมูพิเศษ', 20.00, 2),
(13, 'MN-006', 'กุ้งพิเศษ', 30.00, 1),
(14, 'MN-007', 'หวานน้อย', 0.00, 1),
(15, 'MN-007', 'หวานปกต��', 0.00, 2),
(16, 'MN-007', 'หวานมาก', 0.00, 3),
(17, 'MN-008', 'หวานน้อย', 0.00, 1),
(18, 'MN-008', 'หวานปกติ', 0.00, 2),
(19, 'MN-010', 'กะทิเพิ่ม', 10.00, 1),
(20, 'MN-012', 'ช็อกโกแลต', 10.00, 1),
(21, 'MN-012', 'นมข้น', 5.00, 2);

-- --------------------------------------------------------

--
-- Table structure for table `orders`
--

CREATE TABLE `orders` (
  `id` varchar(20) NOT NULL,
  `table_id` varchar(5) NOT NULL,
  `session_id` varchar(36) DEFAULT NULL,
  `status` enum('pending','cooking','serving','paid','cancelled') NOT NULL DEFAULT 'pending',
  `subtotal` decimal(10,2) NOT NULL DEFAULT 0.00,
  `vat_rate` decimal(4,2) NOT NULL DEFAULT 7.00,
  `vat_amount` decimal(10,2) NOT NULL DEFAULT 0.00,
  `total` decimal(10,2) NOT NULL DEFAULT 0.00,
  `is_paid` tinyint(1) NOT NULL DEFAULT 0,
  `payment_method` enum('promptpay','card','cash') DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `paid_at` datetime DEFAULT NULL,
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `orders`
--

INSERT INTO `orders` (`id`, `table_id`, `session_id`, `status`, `subtotal`, `vat_rate`, `vat_amount`, `total`, `is_paid`, `payment_method`, `created_at`, `paid_at`, `updated_at`) VALUES
('ORD-1774878214262', '01', '8d677588-74cb-4900-a18c-3135ed168e9e', '', 120.00, 7.00, 8.40, 128.40, 0, NULL, '2026-03-30 20:43:34', NULL, '2026-03-30 21:27:31'),
('ORD-1774878452472', '01', '26f2eca5-d3a9-4115-bd11-0a85bcc3464d', '', 70.00, 7.00, 4.90, 74.90, 0, NULL, '2026-03-30 20:47:32', NULL, '2026-03-30 21:27:31'),
('ORD-1774878681418', '02', '88fde036-3b66-4038-a00a-e7c6303db1f0', '', 70.00, 7.00, 4.90, 74.90, 0, NULL, '2026-03-30 20:51:21', NULL, '2026-03-30 21:27:32'),
('ORD-1774879551529', '01', '33cfe642-c70d-4723-84a7-3adf8a657ebb', '', 120.00, 7.00, 8.40, 128.40, 0, NULL, '2026-03-30 21:05:51', NULL, '2026-03-30 21:27:32'),
('ORD-1774883640660', '02', '6019f982-822e-4c9b-88e3-65cf69f0b69c', 'pending', 150.00, 7.00, 10.50, 160.50, 0, NULL, '2026-03-30 22:14:00', NULL, '2026-03-30 22:14:00'),
('ORD-1774978108376', '01', '2f86da32-8456-4a90-9a5d-d7083581d4ba', 'pending', 150.00, 7.00, 10.50, 160.50, 0, NULL, '2026-04-01 00:28:28', NULL, '2026-04-01 00:28:28');

-- --------------------------------------------------------

--
-- Table structure for table `order_items`
--

CREATE TABLE `order_items` (
  `id` int(11) NOT NULL,
  `order_id` varchar(20) NOT NULL,
  `menu_id` varchar(20) NOT NULL,
  `menu_name_th` varchar(100) NOT NULL,
  `unit_price` decimal(8,2) NOT NULL,
  `qty` tinyint(4) NOT NULL DEFAULT 1,
  `extra_price` decimal(8,2) NOT NULL DEFAULT 0.00,
  `line_total` decimal(10,2) NOT NULL,
  `special_note` text DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `order_items`
--

INSERT INTO `order_items` (`id`, `order_id`, `menu_id`, `menu_name_th`, `unit_price`, `qty`, `extra_price`, `line_total`, `special_note`, `created_at`) VALUES
(1, 'ORD-1774878214262', 'MN-006', 'ต้มยำกุ้งน้ำข้น', 120.00, 1, 0.00, 120.00, NULL, '2026-03-30 20:43:34'),
(2, 'ORD-1774878452472', 'MN-004', 'ราดหน้าหมูนุ่ม', 70.00, 1, 0.00, 70.00, NULL, '2026-03-30 20:47:32'),
(3, 'ORD-1774878681418', 'MN-004', 'ราดหน้าหมูนุ่ม', 70.00, 1, 0.00, 70.00, NULL, '2026-03-30 20:51:21'),
(4, 'ORD-1774879551529', 'MN-006', 'ต้มยำกุ้งน้ำข้น', 120.00, 1, 0.00, 120.00, NULL, '2026-03-30 21:05:51'),
(5, 'ORD-1774883640660', 'MN-006', 'ต้มยำกุ้งน้ำข้น', 120.00, 1, 30.00, 150.00, NULL, '2026-03-30 22:14:00'),
(6, 'ORD-1774978108376', 'MN-006', 'ต้มยำกุ้งน้ำข้น', 120.00, 1, 30.00, 150.00, NULL, '2026-04-01 00:28:28');

-- --------------------------------------------------------

--
-- Table structure for table `order_item_toppings`
--

CREATE TABLE `order_item_toppings` (
  `id` int(11) NOT NULL,
  `order_item_id` int(11) NOT NULL,
  `topping_name` varchar(80) NOT NULL,
  `extra_price` decimal(6,2) NOT NULL DEFAULT 0.00
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `order_item_toppings`
--

INSERT INTO `order_item_toppings` (`id`, `order_item_id`, `topping_name`, `extra_price`) VALUES
(1, 5, 'กุ้งพิเศษ', 30.00),
(2, 6, 'กุ้งพิเศษ', 30.00);

-- --------------------------------------------------------

--
-- Table structure for table `restaurant_tables`
--

CREATE TABLE `restaurant_tables` (
  `table_id` varchar(5) NOT NULL,
  `table_name` varchar(50) NOT NULL,
  `capacity` tinyint(4) NOT NULL DEFAULT 4,
  `status` enum('vacant','occupied','cleaning') NOT NULL DEFAULT 'vacant',
  `current_order_id` varchar(20) DEFAULT NULL,
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `restaurant_tables`
--

INSERT INTO `restaurant_tables` (`table_id`, `table_name`, `capacity`, `status`, `current_order_id`, `updated_at`) VALUES
('01', 'Table 01', 4, 'vacant', NULL, '2026-04-01 00:28:43'),
('02', 'Table 02', 4, 'vacant', NULL, '2026-04-01 00:13:01'),
('03', 'Table 03', 4, 'vacant', NULL, '2026-03-30 13:41:19'),
('04', 'Table 04', 2, 'vacant', NULL, '2026-03-30 13:41:19'),
('05', 'Table 05', 4, 'vacant', NULL, '2026-03-30 13:41:19'),
('06', 'Table 06', 6, 'vacant', NULL, '2026-03-30 13:41:19'),
('07', 'Table 07', 4, 'vacant', NULL, '2026-04-01 03:46:27');

-- --------------------------------------------------------

--
-- Table structure for table `reviews`
--

CREATE TABLE `reviews` (
  `id` int(11) NOT NULL,
  `order_id` varchar(20) DEFAULT NULL,
  `table_id` varchar(5) NOT NULL,
  `session_id` varchar(36) DEFAULT NULL,
  `rating` tinyint(4) NOT NULL CHECK (`rating` between 1 and 5),
  `comment` text DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `sales`
--

CREATE TABLE `sales` (
  `id` int(11) NOT NULL,
  `order_id` varchar(20) NOT NULL,
  `table_id` varchar(5) NOT NULL,
  `subtotal` decimal(10,2) NOT NULL,
  `vat_amount` decimal(10,2) NOT NULL,
  `total` decimal(10,2) NOT NULL,
  `payment_method` enum('promptpay','card','cash') NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` varchar(20) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `full_name` varchar(100) NOT NULL,
  `role` enum('admin','chef') NOT NULL DEFAULT 'chef',
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `password`, `full_name`, `role`, `is_active`, `created_at`, `updated_at`) VALUES
('ADM001', 'admin', '$argon2id$v=19$m=19456,t=2,p=1$GxFzOjq4KIWF77ctaJC3ag$wTVk2ezCR6IWT9I7s5YeQ2MlIyPfqL4LMAAsquCM3Pc', 'ผู้ดูแลระบบ', 'admin', 1, '2026-03-30 13:41:19', '2026-03-30 13:41:19'),
('CF001', 'chef1', '$argon2id$v=19$m=19456,t=2,p=1$gunj5vDOuBDBtJjo8C+4bg$JMmt8rG6eSI3UJ4bQD+wg38lh6V6oyKTluXvlNGQzTY', 'Chef One', 'chef', 1, '2026-03-30 13:41:19', '2026-03-30 13:41:19'),
('CHF-1774988348092', 'string', '$argon2id$v=19$m=19456,t=2,p=1$W54mRNjhStjFar6HCouF3A$+KhAVuHL8aUNMonjTSeOGCps7om1pgEKLtlUThQFZpI', 'string', 'chef', 1, '2026-04-01 03:19:08', '2026-04-01 03:19:08');

-- --------------------------------------------------------

--
-- Stand-in structure for view `v_active_orders`
-- (See below for the actual view)
--
CREATE TABLE `v_active_orders` (
`order_id` varchar(20)
,`table_id` varchar(5)
,`table_name` varchar(50)
,`status` enum('pending','cooking','serving','paid','cancelled')
,`total` decimal(10,2)
,`created_at` datetime
,`wait_minutes` bigint(21)
);

-- --------------------------------------------------------

--
-- Structure for view `v_active_orders`
--
DROP TABLE IF EXISTS `v_active_orders`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_active_orders`  AS SELECT `o`.`id` AS `order_id`, `o`.`table_id` AS `table_id`, `t`.`table_name` AS `table_name`, `o`.`status` AS `status`, `o`.`total` AS `total`, `o`.`created_at` AS `created_at`, timestampdiff(MINUTE,`o`.`created_at`,current_timestamp()) AS `wait_minutes` FROM (`orders` `o` join `restaurant_tables` `t` on(`o`.`table_id` = `t`.`table_id`)) WHERE `o`.`status` in ('pending','cooking','serving') ORDER BY `o`.`created_at` ASC ;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `cook_ids`
--
ALTER TABLE `cook_ids`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `customer_sessions`
--
ALTER TABLE `customer_sessions`
  ADD PRIMARY KEY (`session_id`),
  ADD KEY `table_id` (`table_id`),
  ADD KEY `idx_cs_active` (`is_active`);

--
-- Indexes for table `menu_categories`
--
ALTER TABLE `menu_categories`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `code` (`code`);

--
-- Indexes for table `menu_items`
--
ALTER TABLE `menu_items`
  ADD PRIMARY KEY (`id`),
  ADD KEY `category_id` (`category_id`),
  ADD KEY `idx_menu_available` (`is_available`);

--
-- Indexes for table `menu_toppings`
--
ALTER TABLE `menu_toppings`
  ADD PRIMARY KEY (`id`),
  ADD KEY `menu_id` (`menu_id`);

--
-- Indexes for table `orders`
--
ALTER TABLE `orders`
  ADD PRIMARY KEY (`id`),
  ADD KEY `table_id` (`table_id`),
  ADD KEY `session_id` (`session_id`),
  ADD KEY `idx_orders_status` (`status`),
  ADD KEY `idx_orders_created` (`created_at`);

--
-- Indexes for table `order_items`
--
ALTER TABLE `order_items`
  ADD PRIMARY KEY (`id`),
  ADD KEY `menu_id` (`menu_id`),
  ADD KEY `idx_order_items_order` (`order_id`);

--
-- Indexes for table `order_item_toppings`
--
ALTER TABLE `order_item_toppings`
  ADD PRIMARY KEY (`id`),
  ADD KEY `order_item_id` (`order_item_id`);

--
-- Indexes for table `restaurant_tables`
--
ALTER TABLE `restaurant_tables`
  ADD PRIMARY KEY (`table_id`);

--
-- Indexes for table `reviews`
--
ALTER TABLE `reviews`
  ADD PRIMARY KEY (`id`),
  ADD KEY `order_id` (`order_id`),
  ADD KEY `table_id` (`table_id`),
  ADD KEY `session_id` (`session_id`);

--
-- Indexes for table `sales`
--
ALTER TABLE `sales`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `order_id` (`order_id`),
  ADD KEY `table_id` (`table_id`),
  ADD KEY `idx_sales_created` (`created_at`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `menu_categories`
--
ALTER TABLE `menu_categories`
  MODIFY `id` tinyint(4) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `menu_toppings`
--
ALTER TABLE `menu_toppings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=22;

--
-- AUTO_INCREMENT for table `order_items`
--
ALTER TABLE `order_items`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `order_item_toppings`
--
ALTER TABLE `order_item_toppings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `reviews`
--
ALTER TABLE `reviews`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `sales`
--
ALTER TABLE `sales`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `customer_sessions`
--
ALTER TABLE `customer_sessions`
  ADD CONSTRAINT `customer_sessions_ibfk_1` FOREIGN KEY (`table_id`) REFERENCES `restaurant_tables` (`table_id`);

--
-- Constraints for table `menu_items`
--
ALTER TABLE `menu_items`
  ADD CONSTRAINT `menu_items_ibfk_1` FOREIGN KEY (`category_id`) REFERENCES `menu_categories` (`id`);

--
-- Constraints for table `menu_toppings`
--
ALTER TABLE `menu_toppings`
  ADD CONSTRAINT `menu_toppings_ibfk_1` FOREIGN KEY (`menu_id`) REFERENCES `menu_items` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `orders`
--
ALTER TABLE `orders`
  ADD CONSTRAINT `orders_ibfk_1` FOREIGN KEY (`table_id`) REFERENCES `restaurant_tables` (`table_id`),
  ADD CONSTRAINT `orders_ibfk_2` FOREIGN KEY (`session_id`) REFERENCES `customer_sessions` (`session_id`);

--
-- Constraints for table `order_items`
--
ALTER TABLE `order_items`
  ADD CONSTRAINT `order_items_ibfk_1` FOREIGN KEY (`order_id`) REFERENCES `orders` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `order_items_ibfk_2` FOREIGN KEY (`menu_id`) REFERENCES `menu_items` (`id`);

--
-- Constraints for table `order_item_toppings`
--
ALTER TABLE `order_item_toppings`
  ADD CONSTRAINT `order_item_toppings_ibfk_1` FOREIGN KEY (`order_item_id`) REFERENCES `order_items` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `reviews`
--
ALTER TABLE `reviews`
  ADD CONSTRAINT `reviews_ibfk_1` FOREIGN KEY (`order_id`) REFERENCES `orders` (`id`),
  ADD CONSTRAINT `reviews_ibfk_2` FOREIGN KEY (`table_id`) REFERENCES `restaurant_tables` (`table_id`),
  ADD CONSTRAINT `reviews_ibfk_3` FOREIGN KEY (`session_id`) REFERENCES `customer_sessions` (`session_id`);

--
-- Constraints for table `sales`
--
ALTER TABLE `sales`
  ADD CONSTRAINT `sales_ibfk_1` FOREIGN KEY (`order_id`) REFERENCES `orders` (`id`),
  ADD CONSTRAINT `sales_ibfk_2` FOREIGN KEY (`table_id`) REFERENCES `restaurant_tables` (`table_id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
