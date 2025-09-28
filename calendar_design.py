import calendar
from bs4 import BeautifulSoup
class TailwindCalendar(calendar.HTMLCalendar):
    def formatmonth(self, year, month, withyear=True):
        html = super().formatmonth(year, month, withyear)

        # Parse with BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")

        # Remove the month-year heading row
        for row in soup.find_all("tr"):
            if row.find("th", class_="month"):
                row.decompose()

        
        # Inject Tailwind classes
        table = soup.find("table")
        table["class"] = "w-full table-fixed border-collapse border-none rounded-lg shadow-sm"

        for th in soup.find_all("th"):
            th["class"] = "p-2 text-center bg-gray-100 font-semibold"

        for td in soup.find_all("td"):
            td["class"] = "p-2 text-center text-sm"
            if "class" in td.attrs and "noday" in td["class"]:
                td["class"] += " text-gray-300"

        return str(soup)


# Usage
cal = TailwindCalendar()
def calendar_design(year, month):
    return cal.formatmonth(year, month)