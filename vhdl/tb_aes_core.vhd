library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity tb_aes_core is
end tb_aes_core;

architecture test of tb_aes_core is
    signal clk     : std_logic := '0';
    signal rst     : std_logic := '1';
    signal start   : std_logic := '0';
    signal key     : std_logic_vector(255 downto 0) := (others => '0');
    signal data_in : std_logic_vector(127 downto 0) := (others => '0');
    signal data_out: std_logic_vector(127 downto 0);
    signal done    : std_logic;

    component aes_core
        port (
            clk     : in  std_logic;
            rst     : in  std_logic;
            start   : in  std_logic;
            key     : in  std_logic_vector(255 downto 0);
            data_in : in  std_logic_vector(127 downto 0);
            data_out: out std_logic_vector(127 downto 0);
            done    : out std_logic
        );
    end component;

begin
    uut: aes_core port map (
        clk => clk,
        rst => rst,
        start => start,
        key => key,
        data_in => data_in,
        data_out => data_out,
        done => done
    );

    clk_process: process
    begin
        while true loop
            clk <= not clk;
            wait for 10 ns;
        end loop;
    end process;

    stim: process
    begin
        rst <= '1';
        wait for 20 ns;
        rst <= '0';
        key <= x"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        data_in <= x"00112233445566778899AABBCCDDEEFF";
        start <= '1';
        wait for 20 ns;
        start <= '0';
        wait for 100 ns;
        assert done = '1' report "AES done";
        wait;
    end process;
end test;
