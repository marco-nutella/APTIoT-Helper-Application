import flet as ft
from ivss.ivsscalculator import IVSSMainTab
from idses.idsescalculator import IDSESMainTab, IDSESDevice
from pt.ptassistant import PTAssistantMainTab, Organization, APTIoTPenetrationTest
from pt.envsetup import EnvSetupView
from pt.intelgathering import IntelGatheringView
from pt.trafficanalysis import TrafficAnalysisView
from pt.vulnassessment import VulnAssessmentView


def main(page: ft.Page):
    ivss_tab = IVSSMainTab(page)
    idses_tab = IDSESMainTab(page)
    pt_assistant = PTAssistantMainTab(page)
    envsetup_view = EnvSetupView(page)
    intelgathering_view = IntelGatheringView(page)
    trafficanalysis_view = TrafficAnalysisView(page)
    vulnassessment_view = VulnAssessmentView(page)

    selection_tabs = ft.Tabs(
        length=4,
        expand=True,
        content=ft.Column(
            expand=True,
            controls=[
                ft.TabBar(
                    tabs=[
                        ft.Tab(label="IVSS Calculator", icon=ft.Icons.SETTINGS),
                        ft.Tab(label="IDSES Calculator", icon=ft.Icons.SETTINGS),
                        ft.Tab(label="Penetration Testing Assistant", icon=ft.Icons.SETTINGS),
                    ]
                ),
                ft.TabBarView(
                    expand=True,
                    controls=[
                        ft.Container(
                            alignment=ft.Alignment.CENTER,
                            content=ivss_tab.populate(),
                        ),
                        ft.Container(
                            alignment=ft.Alignment.CENTER,
                            content=idses_tab.populate(),
                        ),
                        ft.Container(
                            alignment=ft.Alignment.CENTER,
                            content=pt_assistant.populate(),
                        ),
                    ],
                ),
            ],
        )
    )
    

    #page.add(
    #    ft.SafeArea(
    #        expand=True,
    #        content=ft.Container(
    #            content=selection_tabs,
    #            alignment=ft.Alignment.CENTER,
    #        ),
    #    )
    #)

    def route_change():
        page.views.clear()
        page.views.append(
            ft.View(
                route="/",
                controls=[
                    ft.SafeArea(
                        expand=True,
                        content=ft.Container(
                            content=selection_tabs,
                            alignment=ft.Alignment.CENTER,
                        ),
                    )
                ]
            )
        )
        if page.route == "/envsetup":
            page.views.append(
                ft.View(
                    route="/envsetup",
                    controls=[
                        ft.SafeArea(
                            expand = True,
                            content = envsetup_view.populate()
                        )
                    ]
                )
            )
        if page.route == "/intelgathering":
            page.views.append(
                ft.View(
                    route="/intelgathering",
                    controls=[
                        ft.SafeArea(
                            expand = True,
                            content = intelgathering_view.populate()
                        )
                    ]
                )
            )
        if page.route == "/trafficanalysis":
            page.views.append(
                ft.View(
                    route="/trafficanalysis",
                    controls=[
                        ft.SafeArea(
                            expand = True,
                            content = trafficanalysis_view.populate()
                        )
                    ]
                )
            )
        if page.route == "/vulnassessment":
            page.views.append(
                ft.View(
                    route="/vulnassessment",
                    controls=[
                        ft.SafeArea(
                            expand = True,
                            content = vulnassessment_view.populate()
                        )
                    ]
                )
            )
        page.update()

    async def view_pop(e):
        if e.view is not None:
            print("View pop:", e.view)
            page.views.remove(e.view)
            top_view = page.views[-1]
            await page.push_route(top_view.route)

    route_change()

    def start_test(route:str):
        org = Organization("ISCTE", None)
        device = IDSESDevice("BabyWatcher Mk.4000", "Marty McPerson Inc.", 2026)
        pt_handler = APTIoTPenetrationTest(page, device, org, "Marty McPerson", "01/01/2026")
        page.session.store.set("pt_handler", pt_handler)
        page.navigate(route)

    start_test("/vulnassessment")

    page.on_route_change = route_change
    page.on_view_pop = view_pop


if __name__ == "__main__":
    ft.run(main, assets_dir="assets")
