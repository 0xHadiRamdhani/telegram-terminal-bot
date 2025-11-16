#!/usr/bin/env python3
"""
Cryptocurrency utilities for the Telegram Terminal Bot
Enhanced crypto data fetching and analysis
"""

import asyncio
import aiohttp
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import cryptocompare
import pandas as pd

logger = logging.getLogger(__name__)

class CryptoAnalyzer:
    def __init__(self, api_key: str = None):
        if api_key:
            cryptocompare.cryptocompare._set_api_key_parameter(api_key)
        
        self.base_url = "https://min-api.cryptocompare.com"
        self.session = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def get_multiple_prices(self, coins: List[str], currency: str = 'USD') -> Dict:
        """Get prices for multiple cryptocurrencies"""
        try:
            # Use cryptocompare for multiple coins
            prices = cryptocompare.get_price(coins, currency=currency)
            return prices if prices else {}
            
        except Exception as e:
            logger.error(f"Error getting multiple prices: {e}")
            return {}
    
    async def get_top_cryptocurrencies(self, limit: int = 10) -> List[Dict]:
        """Get top cryptocurrencies by market cap"""
        try:
            # Get top coins data
            top_coins = ['BTC', 'ETH', 'BNB', 'XRP', 'ADA', 'DOGE', 'MATIC', 'SOL', 'DOT', 'AVAX']
            
            prices = await self.get_multiple_prices(top_coins[:limit])
            coin_data = {}
            
            for coin in top_coins[:limit]:
                try:
                    data = cryptocompare.get_coin_data(coin)
                    if data:
                        coin_data[coin] = data
                except:
                    continue
            
            result = []
            for coin in top_coins[:limit]:
                if coin in prices:
                    coin_info = {
                        'symbol': coin,
                        'price': prices[coin][currency],
                        'name': coin_data.get(coin, {}).get('Name', coin),
                        'algorithm': coin_data.get(coin, {}).get('Algorithm', 'N/A'),
                        'proof_type': coin_data.get(coin, {}).get('ProofType', 'N/A')
                    }
                    result.append(coin_info)
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting top cryptocurrencies: {e}")
            return []
    
    async def get_crypto_chart_data(self, coin: str, currency: str = 'USD', days: int = 7) -> Dict:
        """Get chart data for cryptocurrency"""
        try:
            # Get historical data
            hist_data = cryptocompare.get_historical_price_day(coin, currency, limit=days)
            
            if hist_data:
                # Process data for chart
                chart_data = {
                    'timestamps': [],
                    'prices': [],
                    'volumes': [],
                    'market_caps': []
                }
                
                for day in hist_data:
                    chart_data['timestamps'].append(day['time'])
                    chart_data['prices'].append(day['close'])
                    chart_data['volumes'].append(day['volumefrom'])
                
                # Calculate additional metrics
                if len(chart_data['prices']) > 1:
                    current_price = chart_data['prices'][-1]
                    previous_price = chart_data['prices'][-2]
                    change_24h = ((current_price - previous_price) / previous_price) * 100
                    
                    # Calculate volatility
                    prices = chart_data['prices']
                    volatility = self.calculate_volatility(prices)
                    
                    # Calculate trend
                    trend = self.calculate_trend(prices)
                    
                    return {
                        'coin': coin,
                        'currency': currency,
                        'current_price': current_price,
                        'change_24h': change_24h,
                        'volatility': volatility,
                        'trend': trend,
                        'chart_data': chart_data,
                        'period': f"{days} days"
                    }
            
            return {}
            
        except Exception as e:
            logger.error(f"Error getting chart data for {coin}: {e}")
            return {}
    
    def calculate_volatility(self, prices: List[float]) -> float:
        """Calculate price volatility"""
        if len(prices) < 2:
            return 0.0
        
        # Calculate daily returns
        returns = []
        for i in range(1, len(prices)):
            return_pct = (prices[i] - prices[i-1]) / prices[i-1] * 100
            returns.append(return_pct)
        
        # Calculate standard deviation
        if returns:
            mean_return = sum(returns) / len(returns)
            variance = sum((r - mean_return) ** 2 for r in returns) / len(returns)
            volatility = variance ** 0.5
            return volatility
        
        return 0.0
    
    def calculate_trend(self, prices: List[float]) -> str:
        """Calculate price trend"""
        if len(prices) < 3:
            return "neutral"
        
        # Simple moving average comparison
        short_ma = sum(prices[-3:]) / 3
        long_ma = sum(prices[-7:]) / 7 if len(prices) >= 7 else sum(prices) / len(prices)
        
        if short_ma > long_ma * 1.02:
            return "bullish"
        elif short_ma < long_ma * 0.98:
            return "bearish"
        else:
            return "neutral"
    
    async def get_crypto_news(self, coin: str = None) -> List[Dict]:
        """Get cryptocurrency news"""
        try:
            # This would typically use a news API
            # For now, return mock data structure
            mock_news = [
                {
                    'title': f"{coin} Price Analysis",
                    'description': f"Latest price movements and analysis for {coin}",
                    'url': f"https://example.com/{coin.lower()}-news",
                    'published_at': datetime.now().isoformat(),
                    'source': 'Crypto News'
                }
            ]
            
            return mock_news
            
        except Exception as e:
            logger.error(f"Error getting crypto news: {e}")
            return []
    
    async def get_market_overview(self) -> Dict:
        """Get overall cryptocurrency market overview"""
        try:
            # Get Bitcoin dominance
            btc_data = cryptocompare.get_price('BTC', currency='USD', full=True)
            
            # Get total market cap (simplified calculation)
            top_coins = ['BTC', 'ETH', 'BNB', 'XRP', 'ADA']
            total_market_cap = 0
            
            for coin in top_coins:
                try:
                    data = cryptocompare.get_price(coin, currency='USD', full=True)
                    if data and 'RAW' in data and coin in data['RAW']:
                        market_cap = data['RAW'][coin]['USD']['MKTCAP']
                        total_market_cap += market_cap
                except:
                    continue
            
            # Get market sentiment (simplified)
            market_sentiment = "neutral"
            try:
                btc_price = cryptocompare.get_price('BTC', currency='USD')
                if btc_price and 'BTC' in btc_price:
                    btc_change = self.get_24h_change('BTC')
                    if btc_change > 5:
                        market_sentiment = "bullish"
                    elif btc_change < -5:
                        market_sentiment = "bearish"
            except:
                pass
            
            return {
                'total_market_cap': total_market_cap,
                'bitcoin_dominance': 'N/A',  # Would need additional API
                'market_sentiment': market_sentiment,
                'last_updated': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting market overview: {e}")
            return {}
    
    def get_24h_change(self, coin: str, currency: str = 'USD') -> float:
        """Get 24-hour price change percentage"""
        try:
            hist_data = cryptocompare.get_historical_price_hour(coin, currency, limit=24)
            
            if hist_data and len(hist_data) >= 2:
                current_price = hist_data[-1]['close']
                previous_price = hist_data[0]['close']
                change = ((current_price - previous_price) / previous_price) * 100
                return change
            
            return 0.0
            
        except Exception as e:
            logger.error(f"Error getting 24h change for {coin}: {e}")
            return 0.0

class CryptoPortfolio:
    def __init__(self):
        self.holdings = {}
    
    def add_holding(self, coin: str, amount: float, buy_price: float = None) -> bool:
        """Add cryptocurrency holding"""
        try:
            if coin not in self.holdings:
                self.holdings[coin] = []
            
            self.holdings[coin].append({
                'amount': amount,
                'buy_price': buy_price,
                'buy_date': datetime.now().isoformat(),
                'current_value': 0.0,
                'profit_loss': 0.0,
                'profit_loss_pct': 0.0
            })
            
            return True
            
        except Exception as e:
            logger.error(f"Error adding holding: {e}")
            return False
    
    async def update_portfolio_values(self) -> Dict:
        """Update portfolio with current values"""
        try:
            total_value = 0.0
            total_invested = 0.0
            
            for coin, holdings in self.holdings.items():
                current_price = cryptocompare.get_price(coin, currency='USD')
                
                if current_price and coin in current_price:
                    price = current_price[coin]['USD']
                    
                    for holding in holdings:
                        # Update current value
                        holding['current_value'] = holding['amount'] * price
                        
                        # Calculate profit/loss if buy price is available
                        if holding['buy_price']:
                            holding['profit_loss'] = (price - holding['buy_price']) * holding['amount']
                            holding['profit_loss_pct'] = ((price - holding['buy_price']) / holding['buy_price']) * 100
                            total_invested += holding['buy_price'] * holding['amount']
                        
                        total_value += holding['current_value']
            
            return {
                'total_value': total_value,
                'total_invested': total_invested,
                'total_profit_loss': total_value - total_invested,
                'total_profit_loss_pct': ((total_value - total_invested) / total_invested) * 100 if total_invested > 0 else 0,
                'holdings': self.holdings,
                'last_updated': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error updating portfolio values: {e}")
            return {}
    
    def get_portfolio_summary(self) -> Dict:
        """Get portfolio summary"""
        return {
            'total_holdings': len(self.holdings),
            'coins': list(self.holdings.keys()),
            'last_updated': datetime.now().isoformat()
        }