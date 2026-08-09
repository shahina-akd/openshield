from typing import Literal 
from pydantic import BaseModel

class  PackageRef(BaseModel): 
	ecosystem: Literal["npm"] = "npm"
	name: str
	version: str

	@property
	def canonical(self) -> str:
		return f"{self.ecosystem}:{self.name}@{self.version}"

